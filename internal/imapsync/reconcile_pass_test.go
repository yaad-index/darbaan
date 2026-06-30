package imapsync_test

import (
	"context"
	"errors"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// expungeUID permanently removes a message from the upstream INBOX (mark \Deleted
// + EXPUNGE) — simulating a message leaving the source mailbox.
func expungeUID(t *testing.T, addr string, uid uint32) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	require.NoError(t, err)
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()
	require.NoError(t, c.Login(upUser, upPass).Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	sf := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}
	require.NoError(t, c.Store(imap.UIDSetNum(imap.UID(uid)), sf, nil).Close())
	require.NoError(t, c.Expunge().Close())
}

// captureAudit records appended audit entries for assertions.
type captureAudit struct{ recs []audit.Record }

func (c *captureAudit) Append(r audit.Record) error { c.recs = append(c.recs, r); return nil }
func (c *captureAudit) Verify() error               { return nil }
func (c *captureAudit) Close() error                { return nil }

// A message removed from the source is retracted locally, and only that one; a
// retract audit record is written.
func TestReconcileRetractsGoneMessages(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\n1")
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\n2")
	appendMsg(t, user, "From: c@x.test\r\nSubject: three\r\n\r\n3")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)

	expungeUID(t, addr, 2) // UID 2 leaves the source

	aud := &captureAudit{}
	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{Audit: aud})
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "exactly the gone message is retracted")

	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	uids := map[uint32]bool{}
	for _, m := range msgs {
		uids[m.UpstreamUID] = true
	}
	assert.Equal(t, map[uint32]bool{1: true, 3: true}, uids, "present messages stay, the gone one is retracted")

	require.Len(t, aud.recs, 1)
	assert.Equal(t, "retract", aud.recs[0].Event)
	assert.Equal(t, "agent", aud.recs[0].Agent)
}

// Nothing left the source ⇒ nothing retracted.
func TestReconcileNoChange(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\n1")
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\n2")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Zero(t, removed)
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 2)
}

// A UIDVALIDITY mismatch is a mailbox reset (forward re-sync's job), NOT a
// signal that every message was deleted — reconcile must skip, never mass-delete.
func TestReconcileSkipsOnUIDVALIDITYChange(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\n1")
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\n2")

	store := newInbound(t)
	state := newState(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, state, 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)

	expungeUID(t, addr, 1) // a message leaves...

	// ...but the recorded cursor's UIDVALIDITY no longer matches the mailbox's.
	cur, err := state.Load("INBOX")
	require.NoError(t, err)
	require.NoError(t, state.Save("INBOX", imapsync.State{UIDValidity: cur.UIDValidity + 1, LastUID: cur.LastUID}))

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Zero(t, removed, "UIDVALIDITY mismatch ⇒ skip")
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 2, "both records retained on a UIDVALIDITY skip")
}

// A locally-generated record (no upstream UID, e.g. a bounce) is never reconciled,
// even though it is absent from the upstream present-set.
func TestReconcileKeepsLocallyGenerated(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: synced\r\n\r\n1")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)

	_, err = store.Add(inbound.Delivery{
		Owner: "agent", Inbox: inbound.DefaultInbox, From: "MAILER-DAEMON@x", To: "agent@x",
		Subject: "bounce", Raw: []byte("bounce"),
	})
	require.NoError(t, err)

	expungeUID(t, addr, 1) // the synced message leaves the source

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "only the synced message is retracted")

	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, uint32(0), msgs[0].UpstreamUID, "the locally-generated bounce is kept")
}

// A failed listing surfaces an error and retracts nothing (fail-safe) — never
// delete on uncertainty.
func TestReconcileSkipsOnFailedListing(t *testing.T) {
	store := newInbound(t)
	_, _, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 1, UIDValidity: 1,
	})
	require.NoError(t, err)

	down := func() (*imapclient.Client, error) { return nil, errors.New("upstream down") }
	syncer := imapsync.New(down, "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.Error(t, err)
	assert.Zero(t, removed)
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 1, "nothing retracted on a failed listing")
}
