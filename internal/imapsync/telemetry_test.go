package imapsync_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/telemetry/telemetrytest"
)

// Every Sync is one run, counted by outcome with a failure's kind, and timed.
func TestSyncRunsAreRecorded(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "Subject: a\r\n\r\nbody\r\n")
	m, collect := telemetrytest.New(t)

	ok := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	ok.SetMetrics(m)
	_, err := ok.Sync(context.Background())
	require.NoError(t, err)

	refused := func() (*imapclient.Client, error) {
		return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	failing := imapsync.New(refused, "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	failing.SetMetrics(m)
	_, err = failing.Sync(context.Background())
	require.Error(t, err)

	got := collect()
	counts := map[string]int64{}
	for _, p := range got["darbaan.sync.runs"].Points {
		counts[p.Attrs["darbaan.outcome"]+"|"+p.Attrs["error.type"]] = p.Value
	}
	assert.Equal(t, map[string]int64{"ok|": 1, "failed|dial": 1}, counts)
	var timed int64
	for _, p := range got["darbaan.sync.duration"].Points {
		timed += p.Value
	}
	assert.Equal(t, int64(2), timed)
}
