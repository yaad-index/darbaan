package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncHealthSuccessAndSnapshot(t *testing.T) {
	h := newSyncHealth(3)
	base := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return base }

	h.recordSuccess("work", 42, 1000)

	snap := h.snapshot()
	require.Len(t, snap, 1)
	s := snap[0]
	assert.Equal(t, "work", s.Inbox)
	assert.False(t, s.Stalled)
	assert.Equal(t, 0, s.ConsecutiveErrors)
	assert.Equal(t, uint32(42), s.UIDValidity)
	assert.Equal(t, uint32(1000), s.WatermarkUID)
	assert.Equal(t, base.Format(time.RFC3339), s.LastSuccess)
}

// The stall flag flips only when consecutive errors cross the threshold, and the
// reported "since" is the first failure of the streak.
func TestSyncHealthStallThreshold(t *testing.T) {
	h := newSyncHealth(3)
	t0 := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return t0 }

	stalled, n, _ := h.recordFailure("work", errors.New("boom"))
	assert.False(t, stalled)
	assert.Equal(t, 1, n)
	stalled, n, _ = h.recordFailure("work", errors.New("boom"))
	assert.False(t, stalled)
	assert.Equal(t, 2, n)
	stalled, n, since := h.recordFailure("work", errors.New("boom"))
	assert.True(t, stalled, "crosses the threshold at 3")
	assert.Equal(t, 3, n)
	assert.Equal(t, t0, since, "stall-since is the first failure of the streak")

	snap := h.snapshot()
	require.Len(t, snap, 1)
	assert.True(t, snap[0].Stalled)
	assert.Equal(t, "boom", snap[0].LastError)
	assert.Equal(t, 3, snap[0].ConsecutiveErrors)
}

// A successful cycle clears the error streak; a zero UIDVALIDITY (watermark
// unreadable that cycle) keeps the prior watermark rather than clobbering it.
func TestSyncHealthRecoveryKeepsWatermarkOnZero(t *testing.T) {
	h := newSyncHealth(2)
	h.recordSuccess("work", 42, 1000)
	h.recordFailure("work", errors.New("e"))
	h.recordFailure("work", errors.New("e"))
	require.True(t, h.snapshot()[0].Stalled)

	h.recordSuccess("work", 0, 0) // recovered, but watermark not read this cycle

	s := h.snapshot()[0]
	assert.False(t, s.Stalled)
	assert.Equal(t, 0, s.ConsecutiveErrors)
	assert.Empty(t, s.LastError)
	assert.Equal(t, uint32(42), s.UIDValidity, "prior watermark kept when the read failed")
	assert.Equal(t, uint32(1000), s.WatermarkUID)
}

// A threshold below 1 clamps to 1 (one failure stalls); the snapshot is inbox-sorted.
func TestSyncHealthThresholdClampAndSort(t *testing.T) {
	h := newSyncHealth(0)
	stalled, _, _ := h.recordFailure("b", errors.New("e"))
	assert.True(t, stalled, "threshold clamps to 1 so a single failure stalls")
	h.recordSuccess("a", 1, 1)

	snap := h.snapshot()
	require.Len(t, snap, 2)
	assert.Equal(t, "a", snap[0].Inbox, "snapshot is inbox-sorted")
	assert.Equal(t, "b", snap[1].Inbox)
}
