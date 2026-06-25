package sluice_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
)

func newSluice(t *testing.T) *sluice.Sluice {
	t.Helper()
	q, err := sluice.Open(filepath.Join(t.TempDir(), "sluice.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func TestEnqueueListGet(t *testing.T) {
	q := newSluice(t)

	m1, err := q.Enqueue(sluice.Submission{Agent: "agent", From: "f1", Rcpt: []string{"r1"}, Raw: []byte("msg-one")})
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, m1.Status)

	_, err = q.Enqueue(sluice.Submission{Agent: "agent", From: "f2", Rcpt: []string{"r2", "r3"}, Raw: []byte("msg-two")})
	require.NoError(t, err)

	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 2)
	assert.Equal(t, "f1", metas[0].From) // receive order preserved
	assert.Equal(t, 2, len(metas[1].Rcpt))
	assert.Equal(t, len("msg-one"), metas[0].Size)

	got, err := q.Get(m1.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("msg-one"), got.Raw)
	assert.Equal(t, []string{"r1"}, got.Rcpt)
	assert.Equal(t, sluice.StatusPending, got.Status)
}

func TestGetNotFound(t *testing.T) {
	q := newSluice(t)
	_, err := q.Get("999")
	require.ErrorIs(t, err, sluice.ErrNotFound)
	_, err = q.Get("not-a-number")
	require.ErrorIs(t, err, sluice.ErrNotFound)
}

func TestDurableAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")

	q, err := sluice.Open(path)
	require.NoError(t, err)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("persist")})
	require.NoError(t, err)
	require.NoError(t, q.Close())

	q2, err := sluice.Open(path)
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()

	got, err := q2.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("persist"), got.Raw)
}

func TestEnqueueRecordsAuditChain(t *testing.T) {
	q := newSluice(t)
	for i := 0; i < 3; i++ {
		_, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("x")})
		require.NoError(t, err)
	}
	require.NoError(t, q.VerifyAudit())
}

func TestApproveTransitionsAndAudits(t *testing.T) {
	q := newSluice(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	approved, err := q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusApproved, approved.Status)
	assert.Equal(t, "manual", approved.DecidedBy)
	assert.Nil(t, approved.Released) // no edit → original body released

	got, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusApproved, got.Status)
	require.NoError(t, q.VerifyAudit()) // chain still intact across the transition
}

func TestApproveStoresEditedBody(t *testing.T) {
	q := newSluice(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	approved, err := q.Approve(m.ID, "manual", []byte("edited"))
	require.NoError(t, err)
	assert.Equal(t, []byte("edited"), approved.Released)
}

func TestRejectRecordsReason(t *testing.T) {
	q := newSluice(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	rejected, err := q.Reject(m.ID, "manual", "looks like exfiltration", false)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusRejected, rejected.Status)
	assert.Equal(t, "looks like exfiltration", rejected.Reason)
	assert.False(t, rejected.Retryable)
	require.NoError(t, q.VerifyAudit())
}

func TestDoubleDecisionRejected(t *testing.T) {
	q := newSluice(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	_, err = q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)

	// A second verdict on an already-decided message is refused — fail-closed
	// against double decisions.
	_, err = q.Approve(m.ID, "manual", nil)
	require.ErrorIs(t, err, sluice.ErrNotPending)
	_, err = q.Reject(m.ID, "manual", "too late", false)
	require.ErrorIs(t, err, sluice.ErrNotPending)
}

func TestRecordSendAttemptStoresError(t *testing.T) {
	q := newSluice(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)

	out, err := q.RecordSendAttempt(m.ID, errors.New("upstream send pending"))
	require.NoError(t, err)
	assert.Equal(t, "upstream send pending", out.SendErr)
	require.NoError(t, q.VerifyAudit())
}
