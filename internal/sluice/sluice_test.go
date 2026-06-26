package sluice_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// newStore opens a bbolt message store backed by a bbolt audit log, both in a
// temp dir, and returns the store and its audit log.
func newStore(t *testing.T) (sluice.MessageStore, audit.AuditLog) {
	t.Helper()
	al, err := audit.New("bbolt", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })
	return q, al
}

func TestEnqueueListGet(t *testing.T) {
	q, _ := newStore(t)

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

	got, err := q.Get(m1.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("msg-one"), got.Raw)
	assert.Equal(t, []string{"r1"}, got.Rcpt)
}

func TestGetNotFound(t *testing.T) {
	q, _ := newStore(t)
	_, err := q.Get("999")
	require.ErrorIs(t, err, sluice.ErrNotFound)
	_, err = q.Get("not-a-number")
	require.ErrorIs(t, err, sluice.ErrNotFound)
}

func TestDurableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.New("null", "")
	require.NoError(t, err)

	q, err := sluice.New("bbolt", filepath.Join(dir, "s.db"), al)
	require.NoError(t, err)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("persist")})
	require.NoError(t, err)
	require.NoError(t, q.Close())

	q2, err := sluice.New("bbolt", filepath.Join(dir, "s.db"), al)
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()

	got, err := q2.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("persist"), got.Raw)
}

func TestApproveTransitionsAndAudits(t *testing.T) {
	q, al := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	approved, err := q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusApproved, approved.Status)
	assert.Equal(t, "manual", approved.DecidedBy)
	assert.Nil(t, approved.Released)

	require.NoError(t, al.Verify()) // audit chain (enqueue + approve) intact
}

func TestApproveStoresEditedBody(t *testing.T) {
	q, _ := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	approved, err := q.Approve(m.ID, "manual", []byte("edited"))
	require.NoError(t, err)
	assert.Equal(t, []byte("edited"), approved.Released)
}

func TestRejectRecordsReason(t *testing.T) {
	q, al := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	rejected, err := q.Reject(m.ID, "manual", "looks like exfiltration", false)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusRejected, rejected.Status)
	assert.Equal(t, "looks like exfiltration", rejected.Reason)
	require.NoError(t, al.Verify())
}

func TestDoubleDecisionRejected(t *testing.T) {
	q, _ := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	_, err = q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)

	_, err = q.Approve(m.ID, "manual", nil)
	require.ErrorIs(t, err, sluice.ErrNotPending)
	_, err = q.Reject(m.ID, "manual", "too late", false)
	require.ErrorIs(t, err, sluice.ErrNotPending)
}

func TestRecordSendAttemptStoresError(t *testing.T) {
	q, al := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil)
	require.NoError(t, err)

	out, err := q.RecordSendAttempt(m.ID, errors.New("upstream send pending"))
	require.NoError(t, err)
	assert.Equal(t, "upstream send pending", out.SendErr)
	require.NoError(t, al.Verify())
}

// failingAudit always errors on Append, to prove audit is best-effort.
type failingAudit struct{}

func (failingAudit) Append(audit.Record) error { return errors.New("audit down") }
func (failingAudit) Verify() error             { return nil }
func (failingAudit) Close() error              { return nil }

func TestEnqueueSucceedsWhenAuditFails(t *testing.T) {
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), failingAudit{})
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Best-effort: the audit append fails (logged), but the message commits and
	// the operation succeeds — the store is the source of truth.
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("x")})
	require.NoError(t, err)
	got, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, got.Status)
}

// TestTransitionsSucceedWhenAuditFails covers #23: Approve, Reject and
// RecordSendAttempt use the same best-effort writeAudit path as Enqueue, so a
// failing audit must not fail any of them — the commit is the source of truth.
func TestTransitionsSucceedWhenAuditFails(t *testing.T) {
	seedFailing := func(t *testing.T) (sluice.MessageStore, string) {
		t.Helper()
		q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), failingAudit{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = q.Close() })
		m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("x")})
		require.NoError(t, err)
		return q, m.ID
	}

	t.Run("approve", func(t *testing.T) {
		q, id := seedFailing(t)
		out, err := q.Approve(id, "manual", nil)
		require.NoError(t, err)
		assert.Equal(t, sluice.StatusApproved, out.Status)
	})

	t.Run("reject", func(t *testing.T) {
		q, id := seedFailing(t)
		out, err := q.Reject(id, "manual", "no", false)
		require.NoError(t, err)
		assert.Equal(t, sluice.StatusRejected, out.Status)
	})

	t.Run("record send attempt", func(t *testing.T) {
		q, id := seedFailing(t)
		_, err := q.Approve(id, "manual", nil)
		require.NoError(t, err)
		out, err := q.RecordSendAttempt(id, errors.New("upstream send pending"))
		require.NoError(t, err)
		assert.Equal(t, "upstream send pending", out.SendErr)
	})
}

func TestUnknownStoreTypeErrors(t *testing.T) {
	al, err := audit.New("null", "")
	require.NoError(t, err)
	_, err = sluice.New("does-not-exist", "x.db", al)
	require.Error(t, err)
}
