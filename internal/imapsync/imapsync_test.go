package imapsync_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

const upUser, upPass = "agent-up", "pw"

// startUpstream runs an in-process go-imap server with one user + INBOX, and
// returns its address plus the user so a test can append more messages.
func startUpstream(t *testing.T) (string, *imapmemserver.User) {
	t.Helper()
	user := imapmemserver.NewUser(upUser, upPass)
	require.NoError(t, user.Create("INBOX", nil))
	mem := imapmemserver.New()
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), user
}

func appendMsg(t *testing.T, user *imapmemserver.User, raw string) {
	t.Helper()
	_, err := user.Append("INBOX", bytes.NewReader([]byte(raw)), &imap.AppendOptions{})
	require.NoError(t, err)
}

// appendMsgAt appends a message with a specific INTERNALDATE (for SEARCH SINCE).
func appendMsgAt(t *testing.T, user *imapmemserver.User, raw string, when time.Time) {
	t.Helper()
	_, err := user.Append("INBOX", bytes.NewReader([]byte(raw)), &imap.AppendOptions{Time: when})
	require.NoError(t, err)
}

func dialFor(addr string) imapsync.DialFunc {
	return func() (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		if err := c.Login(upUser, upPass).Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}
}

func newInbound(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newState(t *testing.T) imapsync.StateStore {
	t.Helper()
	st, err := imapsync.NewStateStore(filepath.Join(t.TempDir(), "sync.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSyncPullsIncrementally(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: alice@x.test\r\nTo: agent@d.test\r\nSubject: one\r\n\r\nbody one")
	appendMsg(t, user, "From: bob@x.test\r\nTo: agent@d.test\r\nSubject: two\r\n\r\nbody two")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0)

	n, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	msgs, err := store.List("agent")
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	// Headers-only sync: metadata from the envelope, bodies pending (lazy).
	subjects := map[string]bool{msgs[0].Subject: true, msgs[1].Subject: true}
	assert.True(t, subjects["one"] && subjects["two"], "subjects from envelope")
	assert.Equal(t, "agent", msgs[0].Owner) // synced to the agent's mailbox
	assert.True(t, msgs[0].Pending)
	assert.Empty(t, msgs[0].Raw)
	// Envelope + size are stored as metadata (served by the read face without the
	// body): the envelope subject matches and the size is non-zero.
	require.NotNil(t, msgs[0].Envelope)
	assert.True(t, subjects[msgs[0].Envelope.Subject], "envelope subject stored")
	assert.Positive(t, msgs[0].Size)

	// Idempotent: a second sync with no new mail pulls nothing.
	n, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// The body is fetched on demand.
	filled, err := syncer.FetchContent("agent", msgs[0].ID)
	require.NoError(t, err)
	assert.False(t, filled.Pending)
	assert.Contains(t, string(filled.Raw), "body")

	// Only genuinely-new mail is pulled on the next cycle.
	appendMsg(t, user, "From: carol@x.test\r\nSubject: three\r\n\r\nbody three")
	n, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	msgs, _ = store.List("agent")
	assert.Len(t, msgs, 3)
}

// Streaming pulls every message (no Collect-all into memory), and the concrete
// UIDNEXT bound makes a no-new sync return 0 (not via the "N:*" quirk).
func TestSyncStreamsManyMessages(t *testing.T) {
	addr, user := startUpstream(t)
	const n = 25
	for i := 0; i < n; i++ {
		appendMsg(t, user, fmt.Sprintf("Subject: m%d\r\n\r\nbody %d", i, i))
	}
	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0)

	got, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, n, got)
	msgs, err := store.List("agent")
	require.NoError(t, err)
	assert.Len(t, msgs, n)
	for _, m := range msgs {
		assert.True(t, m.Pending) // headers-only
	}

	got, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, got) // concrete bound: last+1 > UIDNEXT-1, no fetch
}

// FetchContent fills a pending (headers-only) record's body from upstream on
// demand, marks it present, and is a no-op on an already-present message.
func TestFetchContentFillsPending(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "Subject: real\r\n\r\nreal body") // upstream UID 1, UIDVALIDITY 1

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0)

	_, m, err := store.AddSyncedPending(inbound.Delivery{Owner: "agent", Subject: "real", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)
	require.True(t, m.Pending)

	filled, err := syncer.FetchContent("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, filled.Pending)
	assert.Contains(t, string(filled.Raw), "real body")

	got, err := store.Get("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, got.Pending)
	assert.Contains(t, string(got.Raw), "real body")

	// Present message → no upstream contact, returned as-is.
	again, err := syncer.FetchContent("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, again.Pending)
}

// A pending record whose UIDVALIDITY no longer matches upstream errors cleanly
// (stale UID) rather than serving wrong/empty content.
func TestFetchContentStaleUIDValidity(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "Subject: x\r\n\r\ny")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0)
	_, m, err := store.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 999})
	require.NoError(t, err)

	_, err = syncer.FetchContent("agent", m.ID)
	require.Error(t, err)
}

// A lost/reset sync cursor re-fetches everything, but the upstream-UID dedup
// (AddSynced) keeps the store free of duplicates — the crash-mid-sync window.
func TestSyncDedupsOnCursorReset(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "Subject: a\r\n\r\nx")
	appendMsg(t, user, "Subject: b\r\n\r\ny")

	store := newInbound(t) // shared across both syncers

	n, err := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0).Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// A second syncer with a FRESH cursor re-fetches both, but dedups: 0 new.
	n, err = imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 0).Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	msgs, err := store.List("agent")
	require.NoError(t, err)
	assert.Len(t, msgs, 2) // no duplicates
}

// A recency cutoff (inbound-max-age) pulls only messages newer than the cutoff
// date; old mail is skipped and the cursor advances past it (no re-pull).
func TestSyncRecencyCutoff(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsgAt(t, user, "Subject: ancient\r\n\r\nx", time.Now().AddDate(-2, 0, 0)) // 2y old
	appendMsgAt(t, user, "Subject: fresh\r\n\r\ny", time.Now())

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t), 365*24*time.Hour) // 1y

	n, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n) // only the fresh message, ancient one skipped
	msgs, err := store.List("agent")
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "fresh", msgs[0].Subject)

	// The cursor advanced past the skipped-old message → next sync is a no-op.
	n, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// A recorded cursor for a different UIDVALIDITY (mailbox reset) is discarded and
// the mailbox re-synced from scratch, despite a high recorded LastUID.
func TestSyncResetsOnUIDValidityMismatch(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: m1\r\n\r\nb1")

	store := newInbound(t)
	state := newState(t)
	require.NoError(t, state.Save("INBOX", imapsync.State{UIDValidity: 424242, LastUID: 99}))

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, state, 0)
	n, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n) // mismatch → cursor reset to 0 → message re-pulled despite LastUID=99

	msgs, _ := store.List("agent")
	require.Len(t, msgs, 1)
}
