package admin_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
)

// GET /sync-status returns each account's health when a reader is wired (#195).
func TestSyncStatusRoundtrip(t *testing.T) {
	svc, _, _ := newSvc(t)
	svc.SetSyncStatusReader(func() []admin.SyncStatus {
		return []admin.SyncStatus{
			{Inbox: "work", LastSuccess: "2026-07-17T12:00:00Z", WatermarkUID: 1000, UIDValidity: 42},
			{Inbox: "stuck", ConsecutiveErrors: 5, LastError: "boom", Stalled: true},
		}
	})
	addr := startServer(t, svc, "secret-token")
	c := admin.NewClient(addr, "secret-token")

	st, err := c.SyncStatus(context.Background())
	require.NoError(t, err)
	require.Len(t, st, 2)
	assert.Equal(t, "work", st[0].Inbox)
	assert.False(t, st[0].Stalled)
	assert.Equal(t, uint32(1000), st[0].WatermarkUID)
	assert.True(t, st[1].Stalled)
	assert.Equal(t, "boom", st[1].LastError)
	assert.Equal(t, 5, st[1].ConsecutiveErrors)
}

// With no reader wired (no inbox syncs), the endpoint answers an empty set — a
// valid answer, not an error.
func TestSyncStatusEmptyWhenNoReader(t *testing.T) {
	svc, _, _ := newSvc(t)
	addr := startServer(t, svc, "tok")
	c := admin.NewClient(addr, "tok")

	st, err := c.SyncStatus(context.Background())
	require.NoError(t, err)
	assert.Empty(t, st, "no reader → empty set, not an error")
}
