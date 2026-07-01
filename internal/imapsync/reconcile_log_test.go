package imapsync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
)

// The cap latch emits a structured "reconcile held" event through the injected
// logger — carrying the inbox (from the injected per-inbox logger) plus the
// candidate/synced/cap attrs. This is the hook the #149 latch-push consumes, and
// it demonstrates the logger is injectable/testable (#151).
func TestReconcileHeldEmitsStructuredEvent(t *testing.T) {
	addr, syncer, _, _ := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ {
		expungeUID(t, addr, uid)
	}

	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	syncer.SetLogger(slog.New(h).With("inbox", "work"))

	_, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.ErrorIs(t, err, imapsync.ErrReconcileHeld)

	var rec map[string]any
	for _, ln := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(ln, &m) == nil && m["msg"] == "reconcile held" {
			rec = m
		}
	}
	require.NotNil(t, rec, "a structured 'reconcile held' record is emitted")
	assert.Equal(t, "WARN", rec["level"])
	assert.Equal(t, "work", rec["inbox"], "inbox comes from the injected per-inbox logger")
	assert.Equal(t, float64(6), rec["candidates"])
	assert.Equal(t, float64(8), rec["synced"])
}
