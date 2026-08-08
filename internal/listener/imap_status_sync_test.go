package listener_test

import (
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/listener"
)

// startIMAPSyncTrigger serves the read face with an on-demand SyncTrigger wired in
// (ADR 0028), so a test can observe STATUS driving the pull.
func startIMAPSyncTrigger(t *testing.T, store inbound.InboundStore, syncNow listener.SyncTrigger) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	filters := map[string]*filter.Filter{inbound.DefaultInbox: nil}
	srv, err := listener.NewIMAPServer(listener.IMAPServerConfig{AllowInsecure: true},
		listener.SingleAuth("agent", "pw"), store, nil, nil, filters, nil, false, nil, syncNow, false)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func addInboundMsg(t *testing.T, store inbound.InboundStore, subject string) {
	t.Helper()
	_, err := store.Add(inbound.Delivery{
		Owner: "agent", Inbox: inbound.DefaultInbox, Subject: subject,
		Raw: []byte("Subject: " + subject + "\r\n\r\nx"),
	})
	require.NoError(t, err)
}

// ADR 0028: STATUS triggers the on-demand pull for the resolved inbox BEFORE the
// counts are computed, so the reply reflects mail the pull brought in. The trigger
// receives the resolved inbox name (not the "INBOX" mailbox alias), and STATUS
// needs no prior SELECT.
func TestStatusTriggersOnDemandSync(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	addInboundMsg(t, store, "existing")

	var gotInbox atomic.Value
	var calls atomic.Int32
	// The trigger stands in for a debounced upstream pull: it records the inbox and
	// lands one new message in the store, exactly as a real Sync would.
	syncNow := func(inbox string) error {
		calls.Add(1)
		gotInbox.Store(inbox)
		addInboundMsg(t, store, "pulled-by-status")
		return nil
	}

	c, err := imapclient.DialInsecure(startIMAPSyncTrigger(t, store, syncNow), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	data, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	require.NoError(t, err)
	require.NotNil(t, data.NumMessages)
	assert.Equal(t, uint32(2), *data.NumMessages, "STATUS count includes the message the pull brought in")
	assert.Equal(t, int32(1), calls.Load(), "STATUS triggered exactly one pull")
	assert.Equal(t, inbound.DefaultInbox, gotInbox.Load(), "trigger gets the resolved inbox name, not INBOX")
}

// A pull error never fails the STATUS: it is best-effort, so STATUS still reports
// the store's current counts (ADR 0028).
func TestStatusSurvivesSyncError(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	addInboundMsg(t, store, "existing")

	syncNow := func(string) error { return assert.AnError }

	c, err := imapclient.DialInsecure(startIMAPSyncTrigger(t, store, syncNow), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())

	data, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	require.NoError(t, err, "a pull error does not fail STATUS")
	require.NotNil(t, data.NumMessages)
	assert.Equal(t, uint32(1), *data.NumMessages)
}

// NOOP stays a true no-op — it never triggers an on-demand pull (ADR 0028: only
// STATUS is the "sync now" verb).
func TestNoopDoesNotTriggerSync(t *testing.T) {
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	addInboundMsg(t, store, "existing")

	var calls atomic.Int32
	syncNow := func(string) error { calls.Add(1); return nil }

	c, err := imapclient.DialInsecure(startIMAPSyncTrigger(t, store, syncNow), nil)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Login("agent", "pw").Wait())
	// Select then NOOP: neither may trigger the on-demand pull.
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.NoError(t, c.Noop().Wait())
	assert.Equal(t, int32(0), calls.Load(), "NOOP does not trigger a pull")
}
