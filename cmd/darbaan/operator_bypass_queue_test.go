package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/opidentity"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// newQueue builds the submission wrapper over a real store, recording every
// release it triggers. This is the seam the SMTP face is handed, so the gating
// asserted here is the gating a submission actually meets.
func newQueue(t *testing.T, entries []string) (*operatorBypassQueue, *[]string) {
	t.Helper()
	al, err := audit.New("null", "")
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })

	ids, err := opidentity.New(entries)
	require.NoError(t, err)

	var released []string
	w := &operatorBypassQueue{
		MessageStore: q,
		identities:   ids,
		release: func(_ context.Context, id string, matched []string) (sluice.Message, error) {
			released = append(released, id)
			m, gerr := q.Get(id)
			return m, gerr
		},
	}
	return w, &released
}

func submit(t *testing.T, w *operatorBypassQueue, rcpt []string) sluice.Message {
	t.Helper()
	m, err := w.Enqueue(sluice.Submission{
		Agent: "agent-a", Inbox: inbound.DefaultInbox, From: "agent@local.test",
		Rcpt: rcpt, Raw: []byte("Subject: s\r\n\r\nb\r\n"),
	})
	require.NoError(t, err, "a submission is always accepted once trapped (ADR 0003)")
	return m
}

// The whole point, and the positive control every negative below depends on.
func TestBypassQueueReleasesWhenEveryRecipientIsAnOperatorIdentity(t *testing.T) {
	w, released := newQueue(t, []string{"op@example.test", "op2@example.test"})
	m := submit(t, w, []string{"op@example.test", "Op Two <OP2@example.test>"})
	assert.Len(t, *released, 1, "every recipient matched, so the hold is skipped")
	assert.Equal(t, m.ID, (*released)[0])
}

// Condition 2: one non-operator recipient sends the WHOLE message down the normal
// path — no partial send, no splitting.
func TestBypassQueueHoldsWhenAnyRecipientIsAStranger(t *testing.T) {
	w, released := newQueue(t, []string{"op@example.test"})

	// Control first: prove this wrapper does release, so the assertion below is
	// about the stranger and not about a wrapper that never releases anything.
	submit(t, w, []string{"op@example.test"})
	require.Len(t, *released, 1, "control: a fully-matching message IS released")

	m := submit(t, w, []string{"op@example.test", "stranger@elsewhere.test"})
	assert.Len(t, *released, 1, "still 1 — the mixed message was held, not released")
	held, err := w.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, held.Status)
}

// 🚨 A message with no recipients must never be released. "Every recipient is an
// operator identity" is vacuously true of none, so this is a bypass that would
// arrive through a condition reading as a restriction.
func TestBypassQueueNeverReleasesAMessageWithNoRecipients(t *testing.T) {
	w, released := newQueue(t, []string{"op@example.test"})

	submit(t, w, []string{"op@example.test"})
	require.Len(t, *released, 1, "control: this wrapper does release matching mail")

	for _, rcpt := range [][]string{nil, {}} {
		m := submit(t, w, rcpt)
		assert.Len(t, *released, 1, "no recipients must not trigger a release")
		held, err := w.Get(m.ID)
		require.NoError(t, err)
		assert.Equal(t, sluice.StatusPending, held.Status)
	}
}

// Condition 4: with no identities configured the wrapper is inert — the default.
func TestBypassQueueWithNoIdentitiesHoldsEverything(t *testing.T) {
	w, released := newQueue(t, nil)
	m := submit(t, w, []string{"op@example.test"})
	assert.Empty(t, *released, "an empty list bypasses nothing, whatever the recipients")
	held, err := w.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, held.Status)
}

// A failed release keeps the submission accepted: the message is already durably
// trapped, so returning an error would invite a client retry that duplicates it.
func TestBypassQueueKeepsSubmissionAcceptedWhenReleaseFails(t *testing.T) {
	al, err := audit.New("null", "")
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })
	ids, err := opidentity.New([]string{"op@example.test"})
	require.NoError(t, err)

	var attempts int
	w := &operatorBypassQueue{
		MessageStore: q, identities: ids,
		release: func(context.Context, string, []string) (sluice.Message, error) {
			attempts++
			return sluice.Message{}, errors.New("release exploded")
		},
	}

	m, err := w.Enqueue(sluice.Submission{
		Agent: "agent-a", Inbox: inbound.DefaultInbox, From: "agent@local.test",
		Rcpt: []string{"op@example.test"}, Raw: []byte("Subject: s\r\n\r\nb\r\n"),
	})
	require.NoError(t, err, "the submission stays accepted")
	require.Equal(t, 1, attempts, "control: a release WAS attempted")
	assert.NotEmpty(t, m.ID, "and the trapped message is returned, so it is not lost")
	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, stored.Status, "it stays in the queue for the operator")
}
