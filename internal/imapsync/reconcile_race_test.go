package imapsync_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// listHookStore wraps an InboundStore and runs a one-shot hook the first time
// List is called, delegating every other method to the embedded store. Reconcile
// calls store.List exactly once per pass, AFTER it has loaded the sync cursor and
// snapshotted the upstream — so the hook injects a real interleaving at that
// window: a concurrent Sync that stores a fresh message and advances the cursor
// while the reconcile pass is mid-flight.
type listHookStore struct {
	inbound.InboundStore
	once sync.Once
	hook func()
}

func (s *listHookStore) List(owner, inbox string) ([]inbound.Message, error) {
	s.once.Do(s.hook)
	return s.InboundStore.List(owner, inbox)
}

// C7: a message that arrives upstream and is stored by a concurrent Sync AFTER
// reconcile's upstream snapshot but BEFORE it lists the store must NOT be
// retracted — its UID is above the cursor reconcile captured before the snapshot,
// so it is too fresh to judge and is left for the next pass. Retracting it would
// be silent permanent loss (the cursor has advanced past its UID, so it is never
// re-pulled). A genuinely-absent message is still retracted in the same pass, so
// the fix narrows retraction to positively-confirmed removals rather than
// disabling it.
func TestReconcileSparesMessageStoredByConcurrentSync(t *testing.T) {
	addr, syncer, store, state := syncN(t, 3) // store {1,2,3}, cursor LastUID=3
	expungeUID(t, addr, 2)                    // UID 2 genuinely leaves upstream

	loaded, err := state.Load("INBOX")
	require.NoError(t, err)
	validity := loaded.UIDValidity

	// The interleaving: while reconcile is mid-pass (cursor already captured at 3,
	// upstream snapshot already taken as {1,3}), a concurrent Sync stores UID 4 and
	// advances the cursor to 4. UID 4 is absent from the snapshot and beyond the
	// pre-snapshot cursor.
	hooked := &listHookStore{InboundStore: store, hook: func() {
		_, _, aerr := store.AddSyncedPending(inbound.Delivery{
			Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 4, UIDValidity: validity,
		})
		require.NoError(t, aerr)
		require.NoError(t, state.Save("INBOX", imapsync.State{UIDValidity: validity, LastUID: 4}))
	}}
	raceSyncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, hooked, state, 0)

	removed, err := raceSyncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "only the genuinely-absent UID 2 is retracted")

	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	uids := uidSet(msgs)
	assert.Contains(t, uids, uint32(4), "the concurrently-stored fresh message survives the race")
	assert.Contains(t, uids, uint32(1))
	assert.Contains(t, uids, uint32(3))
	assert.NotContains(t, uids, uint32(2), "the genuinely-removed message is still retracted")
	_ = syncer
}

// C8: a record left under a SUPERSEDED UIDVALIDITY (the mailbox was reset and
// forward sync has since advanced to the new validity) is orphaned — forward sync
// only ever adds, and the plain set-diff skips other-validity records. Reconcile
// now owns the cleanup: the orphan is retracted, while every current-validity
// record still present upstream is untouched (no over-deletion masquerading as
// orphan reclaim).
func TestReconcileCleansSupersededValidityOrphans(t *testing.T) {
	_, syncer, store, state := syncN(t, 3) // {1,2,3} @ current validity, all present upstream

	loaded, err := state.Load("INBOX")
	require.NoError(t, err)
	staleValidity := loaded.UIDValidity + 1000 // a distinct, superseded validity

	// An orphan from before a UIDVALIDITY reset: its UID is meaningless in the
	// current UID space.
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 99, UIDValidity: staleValidity,
	})
	require.NoError(t, err)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "only the superseded-validity orphan is retracted")

	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	uids := uidSet(msgs)
	assert.Len(t, msgs, 3, "the three current-validity records survive")
	assert.Contains(t, uids, uint32(1))
	assert.Contains(t, uids, uint32(2))
	assert.Contains(t, uids, uint32(3))
	assert.NotContains(t, uids, uint32(99), "the orphan is gone")
}

// C8 (idempotency): re-running reconcile after the orphan is already cleaned
// retracts nothing and leaves the store unchanged — a retry can never compound
// the loss.
func TestReconcileOrphanCleanupIdempotent(t *testing.T) {
	_, syncer, store, state := syncN(t, 2)

	loaded, err := state.Load("INBOX")
	require.NoError(t, err)
	_, _, err = store.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Inbox: inbound.DefaultInbox, UpstreamUID: 77, UIDValidity: loaded.UIDValidity + 1000,
	})
	require.NoError(t, err)

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	removed2, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{})
	require.NoError(t, err)
	assert.Zero(t, removed2, "a second pass finds nothing to retract")

	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Len(t, msgs, 2, "the current-validity records are untouched across retries")
}

func uidSet(msgs []inbound.Message) map[uint32]bool {
	out := make(map[uint32]bool, len(msgs))
	for _, m := range msgs {
		out[m.UpstreamUID] = true
	}
	return out
}
