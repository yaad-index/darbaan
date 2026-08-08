package listener_test

import (
	"bytes"
	"context"
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

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
)

// startE2EUpstream runs an in-process go-imap server (the "real" upstream) with
// one user + INBOX, returning its address and the user so the test can append
// mail mid-run.
func startE2EUpstream(t *testing.T) (string, *imapmemserver.User) {
	t.Helper()
	user := imapmemserver.NewUser("up", "uppw")
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

func e2eAppend(t *testing.T, user *imapmemserver.User, subject string) {
	t.Helper()
	raw := "From: s@x.test\r\nSubject: " + subject + "\r\n\r\nbody"
	_, err := user.Append("INBOX", bytes.NewReader([]byte(raw)), &imap.AppendOptions{})
	require.NoError(t, err)
}

// End-to-end (ADR 0028), all real components — no stubs: a client STATUS drives
// the real listener.Status → real imapsync.OnDemandSync (with its debounce) →
// real imapsync.Syncer → in-process upstream, and the STATUS reply reflects the
// pulled mail. This is the exact path the production wiring runs; it proves the
// trigger fires past the debounce window and silent-skips within it.
func TestOnDemandSyncEndToEnd(t *testing.T) {
	upAddr, upUser := startE2EUpstream(t)
	e2eAppend(t, upUser, "first")

	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	state, err := imapsync.NewStateStore(filepath.Join(t.TempDir(), "sync.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = state.Close() })

	dial := func() (*imapclient.Client, error) {
		c, derr := imapclient.DialInsecure(upAddr, nil)
		if derr != nil {
			return nil, derr
		}
		if derr := c.Login("up", "uppw").Wait(); derr != nil {
			_ = c.Close()
			return nil, derr
		}
		return c, nil
	}
	syncer := imapsync.New(dial, "INBOX", "agent", inbound.DefaultInbox, store, state, 0)

	// Real coordinator with a short (200ms) debounce window so the test can cross it.
	od := imapsync.NewOnDemandSync()
	od.Register(inbound.DefaultInbox, syncer, 200*time.Millisecond)
	syncNow := func(inbox string) error {
		_, _, terr := od.Trigger(context.Background(), inbox)
		return terr
	}

	// Real read face wired exactly as main.go wires it, with the on-demand trigger.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.SingleAuth("agent", "pw"), store, nil, nil,
		map[string]*filter.Filter{inbound.DefaultInbox: nil}, nil, false, nil, syncNow, false)
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	// (1) First STATUS pulls the one upstream message on demand — the store was
	// empty, and STATUS reports it without any background poll having run.
	data, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	require.NoError(t, err)
	require.NotNil(t, data.NumMessages)
	assert.Equal(t, uint32(1), *data.NumMessages, "STATUS pulled the first upstream message on demand")

	// (2) A second message lands upstream, but a STATUS inside the debounce window
	// silent-skips the pull — the count does not yet reflect it.
	e2eAppend(t, upUser, "second")
	data, err = c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	require.NoError(t, err)
	require.NotNil(t, data.NumMessages)
	assert.Equal(t, uint32(1), *data.NumMessages, "STATUS within the 200ms window silent-skips the on-demand pull")

	// (3) Past the window, a STATUS pulls again and the second message appears.
	time.Sleep(220 * time.Millisecond)
	data, err = c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	require.NoError(t, err)
	require.NotNil(t, data.NumMessages)
	assert.Equal(t, uint32(2), *data.NumMessages, "STATUS past the window pulls the second message on demand")
}
