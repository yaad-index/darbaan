package imapsync_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

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
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t))

	n, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	msgs, err := store.List("agent")
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	subjects := map[string]bool{msgs[0].Subject: true, msgs[1].Subject: true}
	assert.True(t, subjects["one"] && subjects["two"], "subjects from envelope")
	assert.Equal(t, "agent", msgs[0].Owner) // synced to the agent's mailbox
	bodies := string(msgs[0].Raw) + string(msgs[1].Raw)
	assert.Contains(t, bodies, "body one") // full raw round-trips

	// Idempotent: a second sync with no new mail pulls nothing.
	n, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

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
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, newState(t))

	got, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, n, got)
	msgs, err := store.List("agent")
	require.NoError(t, err)
	assert.Len(t, msgs, n)

	got, err = syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, got) // concrete bound: last+1 > UIDNEXT-1, no fetch
}

// A recorded cursor for a different UIDVALIDITY (mailbox reset) is discarded and
// the mailbox re-synced from scratch, despite a high recorded LastUID.
func TestSyncResetsOnUIDValidityMismatch(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: m1\r\n\r\nb1")

	store := newInbound(t)
	state := newState(t)
	require.NoError(t, state.Save("INBOX", imapsync.State{UIDValidity: 424242, LastUID: 99}))

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", store, state)
	n, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n) // mismatch → cursor reset to 0 → message re-pulled despite LastUID=99

	msgs, _ := store.List("agent")
	require.Len(t, msgs, 1)
}
