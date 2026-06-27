package listener_test

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
)

func seedInbound(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.Add(inbound.Delivery{
		Owner:   "agent",
		From:    "MAILER-DAEMON@darbaan.test",
		To:      "sender@local",
		Subject: "Undelivered Mail Returned to Sender",
		Raw:     []byte("From: MAILER-DAEMON@darbaan.test\r\nSubject: Undelivered Mail\r\n\r\nrefused-marker\r\n"),
	})
	require.NoError(t, err)
	return s
}

func startIMAP(t *testing.T, store inbound.InboundStore) string {
	return startIMAPWithFetch(t, store, nil)
}

func startIMAPWithFetch(t *testing.T, store inbound.InboundStore, fetch listener.ContentFetch) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.Credential{Username: "agent", Password: "pw"}, store, fetch)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// A body FETCH of a pending (headers-only) record resolves its content on demand
// via the ContentFetch; a flags-only FETCH does not touch the fetcher.
func TestIMAPFetchResolvesPendingOnDemand(t *testing.T) {
	store := seedInbound(t) // present bounce at seq 1
	_, m, err := store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Subject: "lazy", UpstreamUID: 5, UIDValidity: 1,
	})
	require.NoError(t, err) // pending record at seq 2

	var fetchCalls int
	fetch := func(owner, id string) (inbound.Message, error) {
		fetchCalls++
		if id == m.ID { // simulate the on-demand upstream fill
			return store.SetContent(owner, id, []byte("Subject: lazy\r\n\r\nlazy-body"))
		}
		return store.Get(owner, id)
	}

	c, err := imapclient.DialInsecure(startIMAPWithFetch(t, store, fetch), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// Flags-only FETCH: no content needed → fetcher untouched.
	_, err = c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	require.NoError(t, err)
	assert.Equal(t, 0, fetchCalls, "flags-only fetch must not resolve content")

	// BODY[] FETCH of the pending record resolves it on demand.
	msgs, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, string(msgs[0].FindBodySection(&imap.FetchItemBodySection{})), "lazy-body")
	assert.GreaterOrEqual(t, fetchCalls, 1)

	got, err := store.Get("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, got.Pending) // cached present after the on-demand fetch
}

func TestIMAPFetchMarksSeenAndPersists(t *testing.T) {
	store := seedInbound(t)
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	require.NoError(t, c.Login("agent", "pw").Wait())

	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), sel.NumMessages)

	// Non-peek BODY[] fetch returns the bounce and marks it \Seen.
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID:         true,
		Flags:       true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, string(msgs[0].FindBodySection(&imap.FetchItemBodySection{})), "refused-marker")

	got, err := store.Get("agent", "1")
	require.NoError(t, err)
	assert.True(t, got.Seen) // \Seen persisted across the fetch
}

func TestIMAPStoreUnsetSeenPersists(t *testing.T) {
	store := seedInbound(t)
	require.NoError(t, store.SetSeen("agent", "1", true))

	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	_, err = c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsDel, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect()
	require.NoError(t, err)

	got, err := store.Get("agent", "1")
	require.NoError(t, err)
	assert.False(t, got.Seen) // \Seen cleared and persisted
}

func TestIMAPSameSessionSeenSync(t *testing.T) {
	store := seedInbound(t)
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// A non-peek body fetch marks \Seen.
	_, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	require.NoError(t, err)

	// A later FLAGS-only fetch in the SAME session reflects \Seen (not stale).
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0].Flags, imap.FlagSeen)
}

func TestIMAPEmptyMailboxUIDNext(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "empty.db"))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	sel, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), sel.NumMessages)
	assert.Equal(t, imap.UID(1), sel.UIDNext) // UID 0 invalid; empty mailbox → 1
}

func TestIMAPSearch(t *testing.T) {
	store := seedInbound(t) // one unseen message, owner "agent"
	c, err := imapclient.DialInsecure(startIMAP(t, store), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	// SEARCH ALL — previously returned NO [SERVERBUG] (#53).
	all, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, all.AllSeqNums())

	// SEARCH UNSEEN matches; SEARCH SEEN does not (message is unseen).
	unseen, err := c.Search(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, unseen.AllSeqNums())

	seen, err := c.Search(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	require.NoError(t, err)
	assert.Empty(t, seen.AllSeqNums())

	// UID SEARCH ALL returns the message's UID.
	uids, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{1}, uids.AllUIDs())
}

func TestIMAPBadAuthRejected(t *testing.T) {
	c, err := imapclient.DialInsecure(startIMAP(t, seedInbound(t)), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.Error(t, c.Login("agent", "wrong").Wait())
}

func TestIMAPRequiresTLS(t *testing.T) {
	_, err := listener.NewIMAPServer(listener.IMAPServerConfig{},
		listener.Credential{Username: "agent", Password: "pw"}, seedInbound(t), nil)
	require.Error(t, err)
}
