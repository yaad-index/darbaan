package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// The manual approver is compiled in via approvers.go (default build), so the
// strict chain resolves and these tests exercise the real wiring.

func newSeededSluice(t *testing.T) (*sluice.Sluice, string) {
	t.Helper()
	q, err := sluice.Open(filepath.Join(t.TempDir(), "sluice.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", From: "a@local", Rcpt: []string{"b@x.test"}, Raw: []byte("orig")})
	require.NoError(t, err)
	return q, m.ID
}

func router() *policy.Router {
	return policy.NewRouter([]string{"manual"}, []string{"manual"})
}

func TestApproveReachesStubSenderAndNothingLeaves(t *testing.T) {
	q, id := newSeededSluice(t)

	out, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Approve})
	require.NoError(t, err)

	assert.Equal(t, sluice.StatusApproved, out.Status)
	assert.Equal(t, "manual", out.DecidedBy)
	// The stub Sender ran but nothing left: the send error is recorded, not dropped.
	assert.Equal(t, backend.ErrSendPending.Error(), out.SendErr)
	require.NoError(t, q.VerifyAudit())
}

func TestRejectRecordsReason(t *testing.T) {
	q, id := newSeededSluice(t)

	out, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Reject, Reason: "smells like exfiltration", Retryable: false})
	require.NoError(t, err)

	assert.Equal(t, sluice.StatusRejected, out.Status)
	assert.Equal(t, "smells like exfiltration", out.Reason)
	require.NoError(t, q.VerifyAudit())
}

func TestNoDecisionLeavesPending(t *testing.T) {
	q, id := newSeededSluice(t)

	// A Hold verdict (the human took no action) must leave the message pending —
	// fail-closed.
	out, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Hold})
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, out.Status)

	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, got.Status)
}

func TestApproveTwiceIsRefused(t *testing.T) {
	q, id := newSeededSluice(t)

	_, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Approve})
	require.NoError(t, err)

	_, err = decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Approve})
	require.Error(t, err) // already approved, not pending
}
