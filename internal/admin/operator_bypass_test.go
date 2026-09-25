package admin_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// captureLog records every audit row so the bypass trail can be asserted. The
// store and the service are both given this one log, which is how they are wired
// in serve — so the assertions below see the rows in the order an operator would.
type captureLog struct{ rows []audit.Record }

func (c *captureLog) Append(r audit.Record) error { c.rows = append(c.rows, r); return nil }
func (c *captureLog) Verify() error               { return nil }
func (c *captureLog) Close() error                { return nil }

func (c *captureLog) byEvent(event string) (audit.Record, bool) {
	for _, r := range c.rows {
		if r.Event == event {
			return r, true
		}
	}
	return audit.Record{}, false
}

// bypassFixture builds a store + service sharing one capturing audit log, with a
// pending message whose recipients are the operator's own identities.
func bypassFixture(t *testing.T, send func(sluice.Message) error) (*captureLog, sluice.MessageStore, *admin.Service, string) {
	t.Helper()
	cap := &captureLog{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })

	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent-a", Inbox: inbound.DefaultInbox, From: "agent@local.test",
		Rcpt: []string{"op@example.test"}, Raw: []byte("Subject: receipt\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetAuditLog(cap)
	svc.SetSenders(map[string]backend.Sender{inbound.DefaultInbox: senderFunc(send)})
	return cap, q, svc, m.ID
}

// ADR 0034: the message sends without the hold, and the trail says so positively.
func TestOperatorIdentityBypassSendsAndMarksTheTrail(t *testing.T) {
	var sent []sluice.Message
	cap, _, svc, id := bypassFixture(t, func(m sluice.Message) error {
		sent = append(sent, m)
		return nil
	})

	final, err := svc.SendOperatorIdentityBypass(context.Background(), id, []string{"op@example.test"})
	require.NoError(t, err)

	// The send actually happened — the positive control for every "not sent"
	// assertion elsewhere in this file.
	require.Len(t, sent, 1, "the bypass must reach the upstream sender")
	assert.Equal(t, sluice.StatusSent, final.Status)
	assert.Empty(t, final.SendErr)

	// The marker a reader must be able to FIND: a distinct event naming the
	// identity that matched.
	bypass, ok := cap.byEvent("bypass")
	require.True(t, ok, "a bypassed send must be recorded as bypassed, not inferred from an absence")
	assert.Contains(t, bypass.Detail, "op@example.test", "the row names which identity matched")
	assert.Equal(t, "agent-a", bypass.Agent)
	assert.Equal(t, id, bypass.MessageID)

	// 🚨 The marker that protects a reader who finds ONLY the approve row: it must
	// be impossible to read as evidence that a human approved. Actor is empty on
	// this path by design (there is no operator client), so an empty Actor alone
	// would be an ABSENCE — indistinguishable from a missing actor or a bug. The
	// row's own Detail therefore says what supplied the approval.
	approve, ok := cap.byEvent("approve")
	require.True(t, ok)
	assert.Empty(t, approve.Actor, "no operator decided this, so no actor is invented")
	assert.Contains(t, approve.Detail, "operator-identity bypass",
		"the approve row itself must disclose that the bypass supplied it")
	assert.Contains(t, approve.Detail, "ADR 0034")
	assert.Contains(t, final.DecidedBy, "operator-identity bypass",
		"and the persisted record carries it too, for the queue view")

	_, hasSend := cap.byEvent("send_attempt")
	assert.True(t, hasSend, "the delivery itself is still audited")
}

// The DecidedBy stamped on this path names no person, so it can never be mistaken
// for one. Asserted on its own because it is the field an operator reads in a
// listing, where the audit Detail is not visible.
func TestOperatorIdentityBypassNamesNoPerson(t *testing.T) {
	_, _, svc, id := bypassFixture(t, func(sluice.Message) error { return nil })
	final, err := svc.SendOperatorIdentityBypass(context.Background(), id, []string{"op@example.test"})
	require.NoError(t, err)
	assert.NotContains(t, final.DecidedBy, "manual", "not the human approver's name")
	assert.NotEmpty(t, final.DecidedBy, "and not blank, which would read as unknown")
}

// A failed upstream send leaves the message approved with a recorded SendErr —
// re-sendable (C4) — and does NOT fail the caller: the submission was already
// accepted, and a 4xx would invite a retry that duplicates queued mail.
func TestOperatorIdentityBypassSendFailureStaysApprovedAndResendable(t *testing.T) {
	sendErr := errors.New("upstream refused")
	var called int
	cap, _, svc, id := bypassFixture(t, func(sluice.Message) error {
		called++
		return sendErr
	})

	final, err := svc.SendOperatorIdentityBypass(context.Background(), id, []string{"op@example.test"})
	require.NoError(t, err, "a send failure is not a submission failure")
	assert.Equal(t, 1, called, "control: the send was attempted")
	assert.Equal(t, sluice.StatusApproved, final.Status, "stays approved, not sent")
	assert.NotEmpty(t, final.SendErr, "and carries the error, which is what makes it re-sendable")

	// The bypass is still recorded: the marker asserts the path was taken, not that
	// delivery succeeded.
	_, ok := cap.byEvent("bypass")
	assert.True(t, ok)
}

// The transition is pending-only, so a second release cannot send the same message
// twice — the store's ErrNotPending is the guard and this pins it.
func TestOperatorIdentityBypassRefusesNonPending(t *testing.T) {
	var called int
	_, _, svc, id := bypassFixture(t, func(sluice.Message) error { called++; return nil })

	_, err := svc.SendOperatorIdentityBypass(context.Background(), id, []string{"op@example.test"})
	require.NoError(t, err)
	require.Equal(t, 1, called, "control: the first release sent")

	_, err = svc.SendOperatorIdentityBypass(context.Background(), id, []string{"op@example.test"})
	require.Error(t, err, "a second release must be refused")
	assert.ErrorIs(t, err, sluice.ErrNotPending)
	assert.Equal(t, 1, called, "and must not send again")
}
