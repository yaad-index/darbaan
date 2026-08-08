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
	"github.com/yaad-index/darbaan/internal/bounceguard"
	"github.com/yaad-index/darbaan/internal/filter"
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
func (failingInbound) SetContent(string, string, string, []byte) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) SetContentAssessed(string, string, string, []byte, *inbound.Assessment) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) SetKeywords(string, string, string, []string) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) ClearKeywordsDirty(string, string, string) error { return nil }
func (failingInbound) DirtyKeywords(string, string) ([]inbound.Message, error) {
	return nil, nil
}
func (failingInbound) SetHoldDecision(string, string, string, string) (inbound.Message, error) {
	return inbound.Message{}, errors.New("inbound store down")
}
func (failingInbound) List(string, string) ([]inbound.Message, error) { return nil, nil }
func (failingInbound) Get(string, string, string) (inbound.Message, error) {
	return inbound.Message{}, inbound.ErrNotFound
}
func (failingInbound) SetSeen(string, string, string, bool) error { return nil }
func (failingInbound) RemoveSynced(string, string, string) error  { return nil }
func (failingInbound) RekeyOwnersToInbox() (int, error)           { return 0, nil }
func (failingInbound) Close() error                               { return nil }

type senderFunc func(sluice.Message) error

func (f senderFunc) Send(_ context.Context, m sluice.Message) error { return f(m) }

// ADR 0023: an approved message is delivered via the sender of the inbox it was
// submitted as.
func TestApproveDispatchesToInboxSender(t *testing.T) {
	q, defID := seedStore(t) // default-inbox message
	workMsg, err := q.Enqueue(sluice.Submission{Agent: "agent", Inbox: "work", From: "w@x.test", Rcpt: []string{"d@y.test"}, Raw: []byte("w")})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	var workSent, defSent int
	svc.SetSenders(map[string]backend.Sender{
		"work":               senderFunc(func(sluice.Message) error { workSent++; return nil }),
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { defSent++; return nil }),
	})

	_, err = svc.ApproveID(context.Background(), workMsg.ID)
	require.NoError(t, err)
	_, err = svc.ApproveID(context.Background(), defID)
	require.NoError(t, err)
	assert.Equal(t, 1, workSent, "work message → work sender")
	assert.Equal(t, 1, defSent, "default message → default sender")
}

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

	msgs, err := inbox.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	bounce, err := inbox.Get("agent", inbound.DefaultInbox, msgs[0].ID) // List is metadata-only; content via Get
	require.NoError(t, err)
	assert.Contains(t, string(bounce.Raw), "upstream delivery failed permanently")
	assert.NotContains(t, string(bounce.Raw), "mailbox unavailable") // never echo upstream body
	assert.Contains(t, string(bounce.Raw), "DKIM-Signature:")

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

	msgs, _ := inbox.List("agent", inbound.DefaultInbox)
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

	msgs, err := inbox.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "MAILER-DAEMON@darbaan.test", msgs[0].From)
	bounce, err := inbox.Get("agent", inbound.DefaultInbox, msgs[0].ID) // List is metadata-only; content via Get
	require.NoError(t, err)
	assert.Contains(t, string(bounce.Raw), "smells like exfiltration")
	assert.Contains(t, string(bounce.Raw), "5.7.1")
	assert.Contains(t, string(bounce.Raw), "DKIM-Signature:")
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

func TestInboundHoldQueue(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)

	_, _, err = inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1}) // allowed
	require.NoError(t, err)
	_, held, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 2, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)

	list, err := svc.HeldList()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, held.ID, list[0].ID)

	// Expose decides it → off the held list, and the read face would now show it.
	_, err = svc.ExposeHeld(held.ID)
	require.NoError(t, err)
	list, err = svc.HeldList()
	require.NoError(t, err)
	assert.Empty(t, list)

	// Drop also decides (stays hidden) → off the held list.
	_, held2, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 3, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	_, err = svc.DropHeld(held2.ID)
	require.NoError(t, err)
	list, err = svc.HeldList()
	require.NoError(t, err)
	assert.Empty(t, list)
}

// An assessment-held message (ADR 0032) surfaces in the held queue with its
// reason, and one expose decides it — the same human flow as a filter Hold.
func TestInboundHoldQueueIncludesAssessment(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	// A filter that holds nothing, so the assessment is the only hold source.
	flt, err := filter.Compile([]byte("rules: []"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)

	_, m, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)
	_, err = inbox.SetContentAssessed("agent", inbound.DefaultInbox, m.ID,
		[]byte("Subject: x\r\n\r\ny"),
		&inbound.Assessment{Disposition: inbound.AssessmentHeld, Summary: "flagged"})
	require.NoError(t, err)

	list, err := svc.HeldList()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, m.ID, list[0].ID)
	require.NotNil(t, list[0].Assessment)
	assert.Equal(t, "flagged", list[0].Assessment.Summary, "the reason is surfaced for the operator")

	_, err = svc.ExposeHeld(m.ID)
	require.NoError(t, err)
	list, err = svc.HeldList()
	require.NoError(t, err)
	assert.Empty(t, list)
}

// The held queue aggregates across inboxes (ADR 0023), each evaluated by its own
// filter; expose/drop resolves the inbox from the store-wide-unique id.
func TestInboundHoldQueueMultiInbox(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	hold, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{"work": hold, "personal": hold}, func(string) string { return "agent" }, nil, false)

	_, workHeld, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Inbox: "work", UpstreamUID: 1, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	_, persHeld, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Inbox: "personal", UpstreamUID: 1, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	// Same upstream coords but different inbox → distinct records (ADR 0023).
	require.NotEqual(t, workHeld.ID, persHeld.ID)
	// An allowed message in work (no hold label) is not held.
	_, _, err = inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Inbox: "work", UpstreamUID: 2, UIDValidity: 1})
	require.NoError(t, err)

	list, err := svc.HeldList()
	require.NoError(t, err)
	require.Len(t, list, 2) // aggregated across both inboxes

	// ExposeHeld resolves the personal inbox from the id; work's hold remains.
	_, err = svc.ExposeHeld(persHeld.ID)
	require.NoError(t, err)
	list, err = svc.HeldList()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, workHeld.ID, list[0].ID)
	assert.Equal(t, "work", list[0].Inbox)

	// An unknown id resolves to no inbox.
	_, err = svc.ExposeHeld("99999")
	require.ErrorIs(t, err, inbound.ErrNotFound)
}

// Under on_spoof=hold-for-human, a bounce-spoof candidate joins the held queue
// (ADR 0024) alongside filter holds; ordinary mail does not.
func TestInboundBounceGuardHold(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	passthrough, err := filter.Compile([]byte("")) // default-allow, no rules: only the guard holds
	require.NoError(t, err)
	// Verifier says "no valid Darbaan signature" → a bounce-shaped message is a spoof.
	guard := bounceguard.New(func([]byte) (bool, error) { return false, nil })
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: passthrough}, func(string) string { return "agent" }, guard, true /* hold-for-human */)

	// A bounce-shaped message from MAILER-DAEMON (envelope From hits the precheck;
	// the stored raw is bounce-shaped) → spoof → held.
	_, spoof, err := inbox.AddSynced(inbound.Delivery{
		Owner: "agent", UpstreamUID: 1, UIDValidity: 1,
		Envelope: &inbound.Envelope{From: []inbound.Address{{Mailbox: "MAILER-DAEMON", Host: "mail.example"}}},
		Raw:      []byte("From: MAILER-DAEMON@mail.example\r\nSubject: Returned mail\r\n\r\nbounced\r\n"),
	})
	require.NoError(t, err)
	// Ordinary mail (non-candidate From) → no fetch, not a spoof, not held.
	_, _, err = inbox.AddSynced(inbound.Delivery{
		Owner: "agent", UpstreamUID: 2, UIDValidity: 1,
		Envelope: &inbound.Envelope{From: []inbound.Address{{Mailbox: "alice", Host: "example.com"}}},
		Raw:      []byte("From: alice@example.com\r\nSubject: lunch?\r\n\r\nhey\r\n"),
	})
	require.NoError(t, err)

	list, err := svc.HeldList()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, spoof.ID, list[0].ID)

	// Dropping decides it → off the held list.
	_, err = svc.DropHeld(spoof.ID)
	require.NoError(t, err)
	list, err = svc.HeldList()
	require.NoError(t, err)
	assert.Empty(t, list)
}
