package sluice_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// failedSend returns a store holding one approved message whose send failed,
// and the message's id.
func failedSend(t *testing.T, q sluice.MessageStore) string {
	t.Helper()
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("Subject: x\r\n\r\nb")})
	require.NoError(t, err)
	_, err = q.Approve(m.ID, "manual", nil, "", "")
	require.NoError(t, err)
	_, err = q.RecordSendAttempt(m.ID, errors.New("451 try later"), false, "", "")
	require.NoError(t, err)
	return m.ID
}

// A claim needs an approved message with a recorded failure, and only one can
// be held at a time; recording the attempt releases it.
func TestAResendClaimIsExclusiveAndReleasedWithTheOutcome(t *testing.T) {
	q, _ := newStore(t)
	id := failedSend(t, q)

	m, err := q.ClaimResend(id, "op", false)
	require.NoError(t, err)
	assert.Equal(t, "451 try later", m.SendErr, "the failure stays visible while the attempt runs")
	_, err = q.ClaimResend(id, "op", false)
	assert.ErrorIs(t, err, sluice.ErrResendInProgress)
	metas, err := q.List()
	require.NoError(t, err)
	assert.True(t, metas[0].ResendInProgress)

	_, err = q.RecordSendAttempt(id, errors.New("451 again"), true, "op", "")
	require.NoError(t, err)
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Nil(t, got.ResendClaim)
	_, err = q.ClaimResend(id, "op", false)
	assert.NoError(t, err, "a released claim can be taken again")

	_, err = q.RecordSendAttempt(id, nil, true, "op", "")
	require.NoError(t, err)
	_, err = q.ClaimResend(id, "op", false)
	assert.ErrorIs(t, err, sluice.ErrNotResendable, "a sent message is not re-sendable")

	pending, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("x")})
	require.NoError(t, err)
	_, err = q.ClaimResend(pending.ID, "op", false)
	assert.ErrorIs(t, err, sluice.ErrNotResendable, "a pending message is not re-sendable")

	_, err = q.Approve(pending.ID, "manual", nil, "", "")
	require.NoError(t, err)
	_, err = q.ClaimResend(pending.ID, "op", false)
	assert.ErrorIs(t, err, sluice.ErrNotResendable, "an approved message with no recorded failure is not re-sendable")
}

// An attempt that ended with no final reply is recorded with the fixed
// outcome-unknown text, however its error was wrapped, under its own audit
// event.
func TestAnUnknownOutcomeIsRecordedWithItsFixedText(t *testing.T) {
	cap := &capturingAudit{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	id := failedSend(t, q)

	sendErr := fmt.Errorf("backend: send: %w: %w", sluice.ErrOutcomeUnknown, errors.New("connection reset"))
	out, err := q.RecordSendAttempt(id, sendErr, true, "op", "")
	require.NoError(t, err)
	assert.Equal(t, "outcome unknown: no final reply from the server", out.SendErr)
	assert.Equal(t, sluice.StatusApproved, out.Status, "it stays re-sendable")
	metas, err := q.List()
	require.NoError(t, err)
	assert.True(t, metas[0].OutcomeUnknown)
	assert.Equal(t, "resend_outcome_unknown", cap.records[len(cap.records)-1].Event)

	// A first send whose outcome is unknown has its own event too.
	first, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("x")})
	require.NoError(t, err)
	_, err = q.Approve(first.ID, "manual", nil, "", "")
	require.NoError(t, err)
	_, err = q.RecordSendAttempt(first.ID, sendErr, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, "send_outcome_unknown", cap.records[len(cap.records)-1].Event)
}

// A claim still present when the store opens belongs to a process that died
// mid-send: it is cleared, the outcome recorded as unknown, and audited.
func TestALeftoverClaimBecomesAnUnknownOutcomeAtOpen(t *testing.T) {
	cap := &capturingAudit{}
	path := filepath.Join(t.TempDir(), "s.db")
	q, err := sluice.New("bbolt", path, cap)
	require.NoError(t, err)
	id := failedSend(t, q)
	other := failedSend(t, q)
	_, err = q.ClaimResend(id, "op-client", false)
	require.NoError(t, err)
	require.NoError(t, q.Close()) // the process stops mid-send

	q, err = sluice.New("bbolt", path, cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Nil(t, got.ResendClaim)
	assert.Equal(t, "outcome unknown: re-send interrupted", got.SendErr)
	assert.True(t, sluice.IsOutcomeUnknown(got.SendErr))

	untouched, err := q.Get(other)
	require.NoError(t, err)
	assert.Equal(t, "451 try later", untouched.SendErr, "a message with no claim is left as it was")

	last := cap.records[len(cap.records)-1]
	assert.Equal(t, "resend_interrupted", last.Event)
	assert.Equal(t, id, last.MessageID)
	assert.Equal(t, "op-client", last.Actor)

	_, err = q.ClaimResend(id, "op", false)
	assert.ErrorIs(t, err, sluice.ErrAckRequired, "an unknown outcome is not re-sent without the acknowledgement")
	_, err = q.ClaimResend(id, "op", true)
	assert.NoError(t, err, "it stays re-sendable with it")
}
