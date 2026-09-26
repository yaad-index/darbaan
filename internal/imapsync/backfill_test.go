package imapsync_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// #255 fixtures: an upstream with one message whose Message-ID is known, and a
// syncer whose forward-sync cursor has run, so the cursor's validity is the
// server's. It returns that validity.
const backfillMsg = "From: a@x.test\r\nTo: agent@d.test\r\nSubject: one\r\nMessage-ID: <one@x.test>\r\n\r\nbody one"

func syncedBackfillSyncer(t *testing.T) (*imapsync.Syncer, inbound.InboundStore, uint32, string) {
	t.Helper()
	addr, user := startUpstream(t)
	appendMsg(t, user, backfillMsg)
	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	v, _, err := syncer.Watermark()
	require.NoError(t, err)
	require.NotZero(t, v, "precondition: the cursor carries the server's validity")
	return syncer, store, v, addr
}

// legacyPending seeds a pending record for UID 1 that predates the validity field.
func legacyPending(t *testing.T, store inbound.InboundStore, messageID string) string {
	t.Helper()
	d := inbound.Delivery{Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 1}
	if messageID != "" {
		d.Envelope = &inbound.Envelope{MessageID: messageID}
	}
	added, m, err := store.AddSyncedPending(d)
	require.NoError(t, err)
	require.True(t, added)
	require.Zero(t, m.UIDValidity)
	return m.ID
}

func storedValidity(t *testing.T, store inbound.InboundStore, id string) uint32 {
	t.Helper()
	m, err := store.Get("agent", inbound.DefaultInbox, id)
	require.NoError(t, err)
	return m.UIDValidity
}

func TestFetchContentStampsUnknownValidityOnIdentityMatch(t *testing.T) {
	syncer, store, v, _ := syncedBackfillSyncer(t)
	id := legacyPending(t, store, "one@x.test")

	m, err := syncer.FetchContent("agent", inbound.DefaultInbox, id)
	require.NoError(t, err)
	assert.Contains(t, string(m.Raw), "body one", "the content is fetched once the validity is established")
	assert.Equal(t, v, storedValidity(t, store, id), "the validity is stamped from the identity-matched fetch")
}

func TestFetchContentRefusesUnknownValidityOnIdentityMismatch(t *testing.T) {
	syncer, store, _, _ := syncedBackfillSyncer(t)
	id := legacyPending(t, store, "someone-else@x.test")

	_, err := syncer.FetchContent("agent", inbound.DefaultInbox, id)
	require.ErrorIs(t, err, inbound.ErrContentUnavailable)
	assert.Contains(t, err.Error(), "different message")
	assert.NotContains(t, err.Error(), "mailbox reset", "an unknown validity is not a reset")
	assert.Zero(t, storedValidity(t, store, id), "nothing is stamped on a mismatch")
}

// The cursor gate is necessary on its own: without a sync having run, the server's
// validity is not known to be the one the store's UIDs belong to.
func TestFetchContentRefusesUnknownValidityWithoutMatchingCursor(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, backfillMsg)
	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	id := legacyPending(t, store, "one@x.test")

	_, err := syncer.FetchContent("agent", inbound.DefaultInbox, id)
	require.ErrorIs(t, err, inbound.ErrContentUnavailable)
	assert.Contains(t, err.Error(), "sync cursor")
	assert.Zero(t, storedValidity(t, store, id), "a matching Message-ID alone never stamps")
}

func TestFetchContentRefusesUnknownValidityWithoutMessageID(t *testing.T) {
	syncer, store, _, _ := syncedBackfillSyncer(t)
	id := legacyPending(t, store, "")

	_, err := syncer.FetchContent("agent", inbound.DefaultInbox, id)
	require.ErrorIs(t, err, inbound.ErrContentUnavailable)
	assert.Contains(t, err.Error(), "no Message-ID")
	assert.Zero(t, storedValidity(t, store, id), "no identity, no stamp")
}

// The write path: a present legacy record with no stored envelope is identified by
// its stored body's Message-ID header, stamped, and its keyword write then reaches
// the upstream. This is what restores keyword/label replication for those records.
func TestWriteKeywordsStampsUnknownValidityThenStores(t *testing.T) {
	syncer, store, v, addr := syncedBackfillSyncer(t)
	_, legacy, err := store.AddSynced(inbound.Delivery{Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 1, Raw: []byte(backfillMsg)})
	require.NoError(t, err)
	require.Zero(t, legacy.UIDValidity)

	require.NoError(t, syncer.WriteKeywords("agent", inbound.DefaultInbox, legacy.ID, []string{"handled"}, nil))
	assert.Equal(t, v, storedValidity(t, store, legacy.ID))

	flags := upstreamFlags(t, addr)
	assert.Contains(t, flags, imap.Flag("handled"), "the keyword reached the upstream message")
}

// upstreamFlags reads UID 1's flags straight from the upstream server.
func upstreamFlags(t *testing.T, addr string) []imap.Flag {
	t.Helper()
	c, err := dialFor(addr)()
	require.NoError(t, err)
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	var set imap.UIDSet
	set.AddNum(1)
	msgs, err := c.Fetch(set, &imap.FetchOptions{UID: true, Flags: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	return msgs[0].Flags
}

// A dirty record with no Message-ID is retried on every pass; it must be refused
// without opening an upstream session each time.
func TestWriteKeywordsRefusesUnidentifiableRecordWithoutDialing(t *testing.T) {
	dials := 0
	store := newInbound(t)
	syncer := imapsync.New(func() (*imapclient.Client, error) {
		dials++
		return nil, fmt.Errorf("must not dial")
	}, "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	id := legacyPending(t, store, "")

	err := syncer.WriteKeywords("agent", inbound.DefaultInbox, id, []string{"handled"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Message-ID")
	assert.Zero(t, dials, "no session is opened only to refuse")
}
