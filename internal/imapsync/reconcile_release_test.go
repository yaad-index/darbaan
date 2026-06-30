package imapsync_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// Releasing a latched inbox performs the confirmed purge once and clears the
// latch — normal capped operation then resumes (ADR 0026).
func TestReleaseReconcilePurgesAndClears(t *testing.T) {
	addr, syncer, store, state := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ {
		expungeUID(t, addr, uid)
	}

	_, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.ErrorIs(t, err, imapsync.ErrReconcileHeld, "the large purge latches first")

	removed, err := syncer.ReleaseReconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 6, removed, "the confirmed purge completes once")

	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 2, "the 6 gone messages are retracted; the 2 present remain")

	rs, err := state.LoadReconcile("INBOX")
	require.NoError(t, err)
	assert.False(t, rs.Suspended, "the latch is cleared after release")
}

// Release clears the latch even when there is nothing left to purge (e.g. the
// source has since changed) — the operator's release is honored regardless.
func TestReleaseClearsLatchWithNothingToPurge(t *testing.T) {
	_, syncer, store, state := syncN(t, 3) // nothing expunged
	require.NoError(t, state.SaveReconcile("INBOX", imapsync.ReconcileState{Suspended: true, HeldCount: 9}))

	removed, err := syncer.ReleaseReconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Zero(t, removed, "nothing gone upstream ⇒ nothing purged")

	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 3)
	rs, _ := state.LoadReconcile("INBOX")
	assert.False(t, rs.Suspended, "the latch is cleared even with nothing to purge")
}

// The release pass re-lists the upstream FRESH and purges the current gone-set,
// not the snapshot from when it latched — so a change during the hold is
// reflected (here, a 7th message leaves while held → release purges 7, not 6).
// The cap is bypassed for this one pass, so the larger purge does not re-latch.
func TestReleaseUsesFreshUpstreamState(t *testing.T) {
	addr, syncer, store, _ := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ {
		expungeUID(t, addr, uid)
	}
	_, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.ErrorIs(t, err, imapsync.ErrReconcileHeld, "latched at 6")

	expungeUID(t, addr, 7) // a 7th leaves the source during the hold

	removed, err := syncer.ReleaseReconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 7, removed, "release re-lists and purges the CURRENT gone-set (7), not the latched snapshot (6)")
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 1, "only the still-present message (UID 8) remains")
}

// ReconcileLatch exposes the latch for the operator status surface.
func TestReconcileLatchQuery(t *testing.T) {
	addr, syncer, _, _ := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ {
		expungeUID(t, addr, uid)
	}
	_, _ = syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})

	rs, err := syncer.ReconcileLatch()
	require.NoError(t, err)
	assert.True(t, rs.Suspended)
	assert.Equal(t, 6, rs.HeldCount)
}
