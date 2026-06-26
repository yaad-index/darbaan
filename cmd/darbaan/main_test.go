package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/signer"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// The manual approver is compiled in via approvers.go (default build), so the
// strict chain resolves and these tests exercise the real wiring.

func newSeededSluice(t *testing.T) (sluice.MessageStore, string) {
	t.Helper()
	al, err := audit.New("null", "")
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })
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
}

func TestRejectCommitsAndBounceDelivers(t *testing.T) {
	q, id := newSeededSluice(t)
	inbox, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	defer func() { _ = inbox.Close() }()

	m, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Reject, Reason: "smells like exfiltration", Retryable: false})
	require.NoError(t, err)
	require.Equal(t, sluice.StatusRejected, m.Status)

	require.NoError(t, deliverBounce(inbox, testSigner(t), m, "darbaan.test"))

	// A DSN bounce was delivered to the agent's inbound mailbox (ADR 0006),
	// already DKIM-signed (ADR 0007).
	msgs, err := inbox.List("agent") // owner = original submitting agent
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	b := msgs[0]
	assert.Equal(t, "MAILER-DAEMON@darbaan.test", b.From)
	assert.Equal(t, "a@local", b.To) // returned to the original submitter
	assert.False(t, b.Seen)          // lands unseen
	assert.Contains(t, string(b.Raw), "smells like exfiltration")
	assert.Contains(t, string(b.Raw), "5.7.1")           // permanent policy reject
	assert.Contains(t, string(b.Raw), "DKIM-Signature:") // signed before store
}

// TestBounceFailureDistinctFromReject covers #35: a bounce-delivery failure
// must not look like a reject failure — the reject commits regardless.
func TestBounceFailureDistinctFromReject(t *testing.T) {
	q, id := newSeededSluice(t)

	m, err := decideAndApply(context.Background(), q, backend.StubSender{}, router(),
		id, approver.Verdict{Disposition: approver.Reject, Reason: "no", Retryable: false})
	require.NoError(t, err)
	require.Equal(t, sluice.StatusRejected, m.Status)

	// Bounce delivery to a failing store errors distinctly...
	require.Error(t, deliverBounce(failingInbound{}, testSigner(t), m, "darbaan.test"))

	// ...but the reject already stuck (the store still shows it rejected).
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusRejected, got.Status)
}

// failingInbound errors on Add, to prove a bounce-delivery failure is reported
// distinctly from the (already-committed) reject.
type failingInbound struct{}

func (failingInbound) Add(inbound.Delivery) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) List(string) ([]inbound.Message, error) { return nil, nil }
func (failingInbound) Get(string, string) (inbound.Message, error) {
	return inbound.Message{}, inbound.ErrNotFound
}
func (failingInbound) SetSeen(string, string, bool) error { return nil }
func (failingInbound) Close() error                       { return nil }

func testSigner(t *testing.T) *signer.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "dkim.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	s, err := signer.New(path, "darbaan", "darbaan.test")
	require.NoError(t, err)
	return s
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
