package imapsync_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// syncN appends n messages upstream (UIDs 1..n) and syncs them into a fresh
// store, returning the wired syncer, store, and state.
func syncN(t *testing.T, n int) (string, *imapsync.Syncer, inbound.InboundStore, imapsync.StateStore) {
	t.Helper()
	addr, user := startUpstream(t)
	for i := 1; i <= n; i++ {
		appendMsg(t, user, fmt.Sprintf("From: a@x.test\r\nSubject: m%d\r\n\r\n%d", i, i))
	}
	store := newInbound(t)
	state := newState(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, state, 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	return addr, syncer, store, state
}

// The cap latches the inbox when a single pass would retract too much, purging
// nothing and suspending until an operator release (ADR 0026).
func TestReconcileCapLatchesLargePurge(t *testing.T) {
	addr, syncer, store, state := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ { // 6 of 8 leave (>=floor 5, >50%)
		expungeUID(t, addr, uid)
	}

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	assert.ErrorIs(t, err, imapsync.ErrReconcileHeld)
	assert.Zero(t, removed, "a latched pass purges nothing")

	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 8, "nothing is retracted while latched")

	rs, err := state.LoadReconcile("INBOX")
	require.NoError(t, err)
	assert.True(t, rs.Suspended)
	assert.Equal(t, 6, rs.HeldCount)
}

// An already-latched inbox stays held on every pass and never purges — and does
// not even contact the upstream (the failing dialer must not be called).
func TestReconcileStaysHeldWhenSuspended(t *testing.T) {
	store := newInbound(t)
	state := newState(t)
	_, _, err := store.AddSyncedPending(inbound.Delivery{Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)
	require.NoError(t, state.SaveReconcile("INBOX", imapsync.ReconcileState{Suspended: true, HeldCount: 9}))

	failDial := func() (*imapclient.Client, error) { return nil, errors.New("must not dial while held") }
	syncer := imapsync.New(failDial, "INBOX", "agent", inbound.DefaultInbox, store, state, 0)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	assert.ErrorIs(t, err, imapsync.ErrReconcileHeld)
	assert.Zero(t, removed)
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 1)
}

// The floor protects a tiny inbox: removing 1 of 2 (50%) is below the floor, so
// it is a normal retraction, not a latch.
func TestReconcileCapFloorProtectsTinyInbox(t *testing.T) {
	addr, syncer, _, _ := syncN(t, 2)
	expungeUID(t, addr, 1)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err, "below the floor ⇒ no latch")
	assert.Equal(t, 1, removed)
}

// A custom CapFraction is honored: with an 80% cap, a purge the default (50%)
// would latch is allowed through.
func TestReconcileCapFractionOption(t *testing.T) {
	addr, syncer, _, _ := syncN(t, 8)
	for uid := uint32(1); uid <= 5; uid++ { // 5/8: >floor, >50%, but <80%
		expungeUID(t, addr, uid)
	}
	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{CapFraction: 0.8})
	require.NoError(t, err, "5/8 is under an 80% cap ⇒ no latch")
	assert.Equal(t, 5, removed)
}

// A custom CapFloor is honored: a lower floor latches a purge the default floor
// (5) would let through.
func TestReconcileCapFloorOption(t *testing.T) {
	addr, syncer, store, _ := syncN(t, 6)
	for uid := uint32(1); uid <= 4; uid++ { // 4/6: >50%, but below the default floor 5
		expungeUID(t, addr, uid)
	}
	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{CapFloor: 3})
	assert.ErrorIs(t, err, imapsync.ErrReconcileHeld, "floor 3 ⇒ 4 retractions latch")
	assert.Zero(t, removed)
	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 6, "nothing purged while latched")
}

// The reconcile latch round-trips and is independent of the sync cursor — a
// cursor Save must not clear a latch.
func TestReconcileStateIndependentOfCursor(t *testing.T) {
	state := newState(t)

	got, err := state.LoadReconcile("INBOX")
	require.NoError(t, err)
	assert.False(t, got.Suspended, "unset key reads as not-suspended")

	require.NoError(t, state.SaveReconcile("INBOX", imapsync.ReconcileState{Suspended: true, HeldCount: 7}))
	require.NoError(t, state.Save("INBOX", imapsync.State{UIDValidity: 42, LastUID: 99})) // a forward-sync cursor write

	got, err = state.LoadReconcile("INBOX")
	require.NoError(t, err)
	assert.True(t, got.Suspended, "a cursor Save does not clear the latch")
	assert.Equal(t, 7, got.HeldCount)
}
