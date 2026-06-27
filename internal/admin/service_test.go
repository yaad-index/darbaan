package admin_test

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

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/signer"
	"github.com/yaad-index/darbaan/internal/sluice"

	// Compile in the manual approver so the strict chain resolves.
	_ "github.com/yaad-index/darbaan/internal/approver/manual"
)

func seedStore(t *testing.T) (sluice.MessageStore, string) {
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

func newInbound(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testSigner(t *testing.T) *signer.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "dkim.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	s, err := signer.New(path, "darbaan", "darbaan.test")
	require.NoError(t, err)
	return s
}

func strictRouter() *policy.Router { return policy.NewRouter([]string{"manual"}, []string{"manual"}) }

type fakeSender struct{ err error }

func (f fakeSender) Send(context.Context, sluice.Message) error { return f.err }

type failingInbound struct{}

func (failingInbound) Add(inbound.Delivery) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) AddSynced(inbound.Delivery) (bool, inbound.Message, error) {
	return false, inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) AddSyncedPending(inbound.Delivery) (bool, inbound.Message, error) {
	return false, inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) SetContent(string, string, []byte) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) List(string) ([]inbound.Message, error) { return nil, nil }
func (failingInbound) Get(string, string) (inbound.Message, error) {
	return inbound.Message{}, inbound.ErrNotFound
}
func (failingInbound) SetSeen(string, string, bool) error { return nil }
func (failingInbound) Close() error                       { return nil }

func TestApproveStubHoldsDefaultDeny(t *testing.T) {
	q, id := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	assert.Empty(t, out.Warn)
	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusApproved, got.Status) // not sent
}

func TestApproveSuccessMarksSent(t *testing.T) {
	q, id := seedStore(t)
	svc := admin.NewService(q, newInbound(t), fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusSent, got.Status)
}

func TestApprovePermanentFailureBounces(t *testing.T) {
	q, id := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, fakeSender{&smtp.SMTPError{Code: 550, Message: "mailbox unavailable"}}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Warn) // surfaced as a warning, not a failed verdict

	msgs, err := inbox.List("agent")
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Contains(t, string(msgs[0].Raw), "upstream delivery failed permanently")
	assert.NotContains(t, string(msgs[0].Raw), "mailbox unavailable") // never echo upstream body
	assert.Contains(t, string(msgs[0].Raw), "DKIM-Signature:")

	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusApproved, got.Status) // not sent
}

func TestApproveTransientStaysApproved(t *testing.T) {
	q, id := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, fakeSender{&smtp.SMTPError{Code: 451}}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	assert.Contains(t, out.Warn, "transient")

	msgs, _ := inbox.List("agent")
	assert.Empty(t, msgs) // no bounce on transient
	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusApproved, got.Status)
}

func TestRejectDeliversSignedBounce(t *testing.T) {
	q, id := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.RejectID(context.Background(), id, "smells like exfiltration", false)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusRejected), out.Status)
	assert.Empty(t, out.Warn)

	msgs, err := inbox.List("agent")
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "MAILER-DAEMON@darbaan.test", msgs[0].From)
	assert.Contains(t, string(msgs[0].Raw), "smells like exfiltration")
	assert.Contains(t, string(msgs[0].Raw), "5.7.1")
	assert.Contains(t, string(msgs[0].Raw), "DKIM-Signature:")
}

func TestRejectBounceFailureDistinct(t *testing.T) {
	q, id := seedStore(t)
	svc := admin.NewService(q, failingInbound{}, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")

	out, err := svc.RejectID(context.Background(), id, "no", false)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusRejected), out.Status) // reject committed
	assert.Contains(t, out.Warn, "bounce delivery FAILED")     // distinct signal

	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusRejected, got.Status)
}

func TestActOnDecidedMessageErrors(t *testing.T) {
	q, id := seedStore(t)
	svc := admin.NewService(q, newInbound(t), fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")

	_, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	_, err = svc.ApproveID(context.Background(), id) // already decided
	require.ErrorIs(t, err, sluice.ErrNotPending)
}

func TestListAndShow(t *testing.T) {
	q, id := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")

	metas, err := svc.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)

	m, err := svc.Show(id)
	require.NoError(t, err)
	assert.Equal(t, []byte("orig"), m.Raw)

	_, err = svc.Show("999")
	require.ErrorIs(t, err, sluice.ErrNotFound)
}
