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

func TestListSubject(t *testing.T) {
	q, _ := newStore(t)

	// Plain subject, an RFC 2047 encoded-word subject, and no Subject header.
	_, err := q.Enqueue(sluice.Submission{Agent: "a", Raw: []byte("Subject: Hello there\r\n\r\nbody")})
	require.NoError(t, err)
	_, err = q.Enqueue(sluice.Submission{Agent: "a", Raw: []byte("Subject: =?utf-8?q?caf=C3=A9?=\r\n\r\nbody")})
	require.NoError(t, err)
	_, err = q.Enqueue(sluice.Submission{Agent: "a", Raw: []byte("From: x\r\n\r\nno subject header")})
	require.NoError(t, err)

	metas, err := q.List()
	require.NoError(t, err)
	got := map[string]bool{}
	for _, m := range metas {
		got[m.Subject] = true
	}
	assert.True(t, got["Hello there"], "plain subject parsed")
	assert.True(t, got["café"], "RFC 2047 encoded-word decoded")
	assert.True(t, got[""], "absent subject yields empty, not an error")
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

	approved, err := q.Approve(m.ID, "manual", nil, "", "")
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

	approved, err := q.Approve(m.ID, "manual", []byte("edited"), "", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("edited"), approved.Released)
}

func TestRejectRecordsReason(t *testing.T) {
	q, al := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	rejected, err := q.Reject(m.ID, "manual", "looks like exfiltration", false, "")
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusRejected, rejected.Status)
	assert.Equal(t, "looks like exfiltration", rejected.Reason)
	require.NoError(t, al.Verify())
}

func TestDoubleDecisionRejected(t *testing.T) {
	q, _ := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	_, err = q.Approve(m.ID, "manual", nil, "", "")
	require.NoError(t, err)

	_, err = q.Approve(m.ID, "manual", nil, "", "")
	require.ErrorIs(t, err, sluice.ErrNotPending)
	_, err = q.Reject(m.ID, "manual", "too late", false, "")
	require.ErrorIs(t, err, sluice.ErrNotPending)
}

func TestRecordSendAttemptStoresError(t *testing.T) {
	q, al := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil, "", "")
	require.NoError(t, err)

	out, err := q.RecordSendAttempt(m.ID, errors.New("upstream send pending"), false, "", "")
	require.NoError(t, err)
	assert.Equal(t, "upstream send pending", out.SendErr)
	require.NoError(t, al.Verify())
}

// C26: a send is only ever recorded against an approved message (idempotently once
// sent). A pending or rejected message must refuse the stamp, so the re-send verb
// can never resurrect a non-approved record.
func TestRecordSendAttemptRejectsNonApproved(t *testing.T) {
	q, _ := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	// Pending → refused.
	_, err = q.RecordSendAttempt(m.ID, errors.New("boom"), false, "", "")
	require.ErrorIs(t, err, sluice.ErrNotApproved)

	// Rejected → refused.
	_, err = q.Reject(m.ID, "manual", "no", false, "")
	require.NoError(t, err)
	_, err = q.RecordSendAttempt(m.ID, errors.New("boom"), false, "", "")
	require.ErrorIs(t, err, sluice.ErrNotApproved)

	// Approved → allowed; and idempotent once sent.
	m2, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("two")})
	require.NoError(t, err)
	_, err = q.Approve(m2.ID, "manual", nil, "", "")
	require.NoError(t, err)
	sent, err := q.RecordSendAttempt(m2.ID, nil, false, "", "")
	require.NoError(t, err)
	require.Equal(t, sluice.StatusSent, sent.Status)
	_, err = q.RecordSendAttempt(m2.ID, nil, false, "", "") // idempotent on an already-sent message
	require.NoError(t, err)

	// A failure recorded against an already-sent message is refused — a losing
	// concurrent second attempt can never turn a delivered message into
	// sent-with-error (review note).
	_, err = q.RecordSendAttempt(m2.ID, errors.New("late failure"), true, "", "")
	require.ErrorIs(t, err, sluice.ErrNotApproved)
	after, err := q.Get(m2.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusSent, after.Status)
	assert.Empty(t, after.SendErr, "a sent message keeps no send error")
}

// C21: the listing view surfaces the routed inbox and the last send error, so an
// approved-but-stranded message (and which inbox it routed through) is visible.
func TestListSurfacesInboxAndSendErr(t *testing.T) {
	q, _ := newStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Inbox: "work", From: "f", Raw: []byte("Subject: s\r\n\r\nb")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil, "", "")
	require.NoError(t, err)
	_, err = q.RecordSendAttempt(m.ID, errors.New("451 temporary failure"), false, "", "")
	require.NoError(t, err)

	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "work", metas[0].Inbox)
	assert.Equal(t, "451 temporary failure", metas[0].SendErr)
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
		out, err := q.Approve(id, "manual", nil, "", "")
		require.NoError(t, err)
		assert.Equal(t, sluice.StatusApproved, out.Status)
	})

	t.Run("reject", func(t *testing.T) {
		q, id := seedFailing(t)
		out, err := q.Reject(id, "manual", "no", false, "")
		require.NoError(t, err)
		assert.Equal(t, sluice.StatusRejected, out.Status)
	})

	t.Run("record send attempt", func(t *testing.T) {
		q, id := seedFailing(t)
		_, err := q.Approve(id, "manual", nil, "", "")
		require.NoError(t, err)
		out, err := q.RecordSendAttempt(id, errors.New("upstream send pending"), false, "", "")
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

type capturingAudit struct{ records []audit.Record }

func (c *capturingAudit) Append(r audit.Record) error { c.records = append(c.records, r); return nil }
func (c *capturingAudit) Verify() error               { return nil }
func (c *capturingAudit) Close() error                { return nil }

// ADR 0027: an enqueue audit row records the acting agent and the routed inbox.
func TestEnqueueAuditRecordsAgentAndInbox(t *testing.T) {
	cap := &capturingAudit{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	_, err = q.Enqueue(sluice.Submission{Agent: "agent-a", Inbox: "work", Raw: []byte("Subject: x\r\n\r\nb")})
	require.NoError(t, err)

	require.Len(t, cap.records, 1)
	assert.Equal(t, "enqueue", cap.records[0].Event)
	assert.Equal(t, "agent-a", cap.records[0].Agent)
	assert.Equal(t, "work", cap.records[0].Inbox)
	assert.Empty(t, cap.records[0].Actor, "enqueue is agent-originated: no operator actor")
}

// C30/C16: an approve + send audits the deciding operator client (Actor) and, for
// an ApproveAs, the send identity in the send-attempt Detail.
func TestApproveSendAuditRecordsActorAndIdentity(t *testing.T) {
	cap := &capturingAudit{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	m, err := q.Enqueue(sluice.Submission{Agent: "agent-a", Inbox: "work", Raw: []byte("Subject: x\r\n\r\nb")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil, "work", "ops-alice")
	require.NoError(t, err)
	_, err = q.RecordSendAttempt(m.ID, nil, false, "ops-alice", "work@example.test")
	require.NoError(t, err)

	byEvent := map[string]audit.Record{}
	for _, r := range cap.records {
		byEvent[r.Event] = r
	}
	require.Contains(t, byEvent, "approve")
	assert.Equal(t, "ops-alice", byEvent["approve"].Actor)
	require.Contains(t, byEvent, "send_attempt")
	assert.Equal(t, "ops-alice", byEvent["send_attempt"].Actor)
	assert.Equal(t, "sent as work@example.test", byEvent["send_attempt"].Detail)
}

// C28: a reject audits its permanence via the Retryable flag — set on reject rows,
// nil on rows the flag does not describe.
func TestRejectAuditRecordsRetryableFlag(t *testing.T) {
	cap := &capturingAudit{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	m, err := q.Enqueue(sluice.Submission{Agent: "agent-a", Raw: []byte("Subject: x\r\n\r\nb")})
	require.NoError(t, err)
	_, err = q.Reject(m.ID, "manual", "exfiltration", false, "ops-bob")
	require.NoError(t, err)

	var reject *audit.Record
	for i := range cap.records {
		if cap.records[i].Event == "reject" {
			reject = &cap.records[i]
		}
	}
	require.NotNil(t, reject)
	assert.Equal(t, "ops-bob", reject.Actor)
	require.NotNil(t, reject.Retryable, "reject records the permanence flag")
	assert.False(t, *reject.Retryable, "a permanent reject records retryable=false")
	// The enqueue row is not a reject: the flag does not apply and stays nil.
	assert.Nil(t, cap.records[0].Retryable)
}
