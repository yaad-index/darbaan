package telegram

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/admin"
)

func TestFormatLatch(t *testing.T) {
	s := formatLatch(admin.ReconcileStatus{Inbox: "work", Suspended: true, HeldCount: 42})
	assert.Contains(t, s, "Reconciliation held")
	assert.Contains(t, s, `"work"`)
	assert.Contains(t, s, "42 message(s)")
	assert.Contains(t, s, "nothing has been purged") // the latch is non-destructive
	assert.Contains(t, s, "darbaan reconcile release work")
	// Notification-only: no inline keyboard / one-tap release is offered (#149).
	assert.NotContains(t, s, "button")
}

// The dedup/re-notify cycle that matters most (#149): a latched inbox is alerted
// once; when it is no longer suspended (released) the dedup entry is cleared, so a
// fresh latch re-notifies. This exercises seenLatch / markPostedLatch /
// pruneLatched exactly as pollReconcile drives them across poll cycles.
func TestLatchDedupReNotifyCycle(t *testing.T) {
	c := &Client{postedLatches: map[string]bool{}}
	latched := []admin.ReconcileStatus{{Inbox: "work", Suspended: true, HeldCount: 5}}
	released := []admin.ReconcileStatus{{Inbox: "work", Suspended: false}}

	// Cycle 1 — first latch: not yet seen → alert, then mark.
	c.pruneLatched(latched)
	assert.False(t, c.seenLatch("work"), "first latch is unseen → alerts")
	c.markPostedLatch("work")

	// Cycle 2 — still latched: already seen → no re-alert (post-once).
	c.pruneLatched(latched)
	assert.True(t, c.seenLatch("work"), "still-latched inbox stays deduped")

	// Cycle 3 — released (no longer suspended): dedup entry is pruned.
	c.pruneLatched(released)
	assert.False(t, c.seenLatch("work"), "release clears the dedup entry")

	// Cycle 4 — fresh latch after the release: unseen again → re-alerts.
	c.pruneLatched(latched)
	assert.False(t, c.seenLatch("work"), "a re-latch after release notifies again")
	c.markPostedLatch("work")
	assert.True(t, c.seenLatch("work"))
}

// pruneLatched keeps still-suspended inboxes and drops only the ones that have
// dropped out of the suspended set, independent of other inboxes.
func TestPruneLatchedIsPerInbox(t *testing.T) {
	c := &Client{postedLatches: map[string]bool{"work": true, "personal": true}}
	// work still suspended, personal released; a third inbox not previously alerted.
	c.pruneLatched([]admin.ReconcileStatus{
		{Inbox: "work", Suspended: true, HeldCount: 3},
		{Inbox: "personal", Suspended: false},
		{Inbox: "team", Suspended: true, HeldCount: 9},
	})
	assert.True(t, c.seenLatch("work"), "still-suspended inbox kept")
	assert.False(t, c.seenLatch("personal"), "released inbox pruned")
	assert.False(t, c.seenLatch("team"), "prune never adds entries")
}
