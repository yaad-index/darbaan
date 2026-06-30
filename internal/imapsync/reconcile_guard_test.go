package imapsync_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// Release refuses a non-held inbox. Without the guard, release runs cap-bypassed,
// so releasing an inbox the cap never latched would purge a large gone-set with
// no safety check — release must require an actual latch first (#154).
func TestReleaseRejectsNonHeld(t *testing.T) {
	addr, syncer, store, state := syncN(t, 8)
	for uid := uint32(1); uid <= 6; uid++ {
		expungeUID(t, addr, uid) // a large removal — but the inbox was never latched
	}

	removed, err := syncer.ReleaseReconcile(context.Background(), imapsync.ReconcileOptions{})
	assert.ErrorIs(t, err, imapsync.ErrReconcileNotHeld)
	assert.Zero(t, removed, "release on a non-held inbox purges nothing")

	msgs, _ := store.List("agent", inbound.DefaultInbox)
	assert.Len(t, msgs, 8, "no cap-bypassed purge on a non-held inbox")

	rs, err := state.LoadReconcile("INBOX")
	require.NoError(t, err)
	assert.False(t, rs.Suspended, "a refused release leaves the (unset) latch untouched")
}
