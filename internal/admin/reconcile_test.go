package admin_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/backend"
)

// Without reconcile controls wired (no inbox has an upstream), both endpoints
// report ErrReconcileUnavailable (ADR 0026).
func TestReconcileControlsUnavailable(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")

	_, err := svc.ReconcileStatusAll()
	assert.ErrorIs(t, err, admin.ErrReconcileUnavailable)
	_, err = svc.ReleaseReconcile(context.Background(), "work")
	assert.ErrorIs(t, err, admin.ErrReconcileUnavailable)
}

// The reconcile status/release endpoints round-trip client → server → service →
// the wired callbacks (ADR 0026).
func TestReconcileControlsRoundtrip(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	released := ""
	svc.SetReconcileControls(
		func(_ context.Context, inbox string) (int, error) { released = inbox; return 4, nil },
		func() ([]admin.ReconcileStatus, error) {
			return []admin.ReconcileStatus{{Inbox: "work", Suspended: true, HeldCount: 9}}, nil
		},
	)
	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	st, err := c.ReconcileStatus(ctx)
	require.NoError(t, err)
	require.Len(t, st, 1)
	assert.Equal(t, "work", st[0].Inbox)
	assert.True(t, st[0].Suspended)
	assert.Equal(t, 9, st[0].HeldCount)

	res, err := c.ReleaseReconcile(ctx, "work")
	require.NoError(t, err)
	assert.Equal(t, "work", res.Inbox)
	assert.Equal(t, 4, res.Purged)
	assert.Equal(t, "work", released, "the release callback received the inbox name")
}

// Over HTTP, an unwired control surfaces as an error to the client (503).
func TestReconcileUnavailableOverHTTP(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	_, err := c.ReconcileStatus(ctx)
	require.Error(t, err)
	_, err = c.ReleaseReconcile(ctx, "work")
	require.Error(t, err)
}

// Releasing a non-held inbox surfaces as an error to the client (the service
// returns ErrReconcileNotHeld → 409).
func TestReconcileReleaseNotHeldOverHTTP(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetReconcileControls(
		func(_ context.Context, _ string) (int, error) { return 0, admin.ErrReconcileNotHeld },
		func() ([]admin.ReconcileStatus, error) { return nil, nil },
	)
	c := admin.NewClient(startServer(t, svc, "tok"), "tok")

	_, err := c.ReleaseReconcile(context.Background(), "work")
	require.Error(t, err)
}
