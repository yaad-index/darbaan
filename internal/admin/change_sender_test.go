package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// C4: a message stranded in `approved` by a transient send failure can be
// recovered by the re-send verb — a plain re-approve would hit ErrNotPending.
func TestReSendRecoversStrandedApproved(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: a@x.test\r\n\r\nb\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	fail := true
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error {
			if fail {
				return errors.New("dial tcp: connection refused") // transient, not permanent
			}
			return nil
		}),
	})

	// First approve strands it: the transient failure keeps it approved with a SendErr.
	out, err := svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	require.Equal(t, string(sluice.StatusApproved), out.Status)
	stranded, err := q.Get(m.ID)
	require.NoError(t, err)
	require.NotEmpty(t, stranded.SendErr)

	// Re-send now delivers and clears the error.
	fail = false
	out, err = svc.ReSend(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	sent, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusSent, sent.Status)
	assert.Empty(t, sent.SendErr)
}

// C4 (review fix): a re-send of an approved-AS message that stranded must deliver
// the operator's chosen identity — recomputed from the persisted AsInbox — not
// silently revert to the original From.
func TestReSendApprovedAsRecomputesIdentity(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "assistant@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: assistant@x.test\r\nTo: d@y.test\r\nSubject: hi\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	fail := true
	var sentVia string
	var sent sluice.Message
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(msg sluice.Message) error { sentVia = "default"; sent = msg; return nil }),
		"work": senderFunc(func(msg sluice.Message) error {
			if fail {
				return errors.New("dial tcp: connection refused") // transient
			}
			sentVia = "work"
			sent = msg
			return nil
		}),
	})
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "default@x.test", "work": "work@x.test"})

	// ApproveAs work, but the send fails transiently → stranded approved-as.
	out, err := svc.ApproveAs(context.Background(), m.ID, "work")
	require.NoError(t, err)
	require.Equal(t, string(sluice.StatusApproved), out.Status)
	stranded, err := q.Get(m.ID)
	require.NoError(t, err)
	require.Equal(t, "work", stranded.AsInbox, "the as-choice is persisted for recovery")
	require.NotEmpty(t, stranded.SendErr)

	// Re-send delivers via the chosen inbox with the rewritten From — never the original.
	fail = false
	out, err = svc.ReSend(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	assert.Equal(t, "work", sentVia, "re-send routes through the chosen inbox's sender")
	assert.Equal(t, "work@x.test", sent.From, "envelope From recomputed to the chosen identity")
	assert.Contains(t, string(sent.Released), "From: work@x.test", "header From recomputed")
	assert.NotContains(t, string(sent.Released), "assistant@x.test")

	// The stored record still keeps the original From (send-time rewrite only).
	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, "assistant@x.test", stored.From)
}

// C4 (review fix): if the approved-as inbox no longer resolves (removed from config
// while the message was stranded), the re-send is refused fail-closed rather than
// delivered under the original identity.
func TestReSendApprovedAsRefusesVanishedInbox(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "assistant@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: assistant@x.test\r\nTo: d@y.test\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { return nil }),
		"work":               senderFunc(func(sluice.Message) error { return errors.New("dial tcp: connection refused") }),
	})
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "default@x.test", "work": "work@x.test"})

	// Strand it as approved-as work.
	_, err = svc.ApproveAs(context.Background(), m.ID, "work")
	require.NoError(t, err)

	// The work inbox is removed from config before the operator retries.
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "default@x.test"})

	_, err = svc.ReSend(context.Background(), m.ID)
	assert.ErrorIs(t, err, admin.ErrUnknownInbox)

	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusApproved, stored.Status, "refused re-send leaves it approved, not delivered under the wrong identity")
}

// C25: a message stamped with an inbox whose sender was removed from config is
// refused rather than silently delivered through the default account — it stays
// approved, warned, and re-sendable (SendErr set) once the inbox is restored.
func TestApproveRefusesSendWhenInboxSenderRemoved(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: "work", From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: a@x.test\r\n\r\nb\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	var defaultUsed bool
	// The "work" inbox's sender is gone; only the default remains.
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { defaultUsed = true; return nil }),
	})

	out, err := svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusApproved), out.Status, "a refused send stays approved")
	assert.NotEmpty(t, out.Warn, "the operator is warned")
	assert.False(t, defaultUsed, "must NOT fall back to the default account")

	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusApproved, stored.Status)
	assert.NotEmpty(t, stored.SendErr, "the refusal is visible and re-sendable")
}

// C25: the same refusal guards the re-send path — a plain-approved message whose
// inbox sender vanished while stranded is refused, not delivered via the default.
func TestReSendRefusesWhenInboxSenderRemoved(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: "work", From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: a@x.test\r\n\r\nb\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { return nil }),
		"work":               senderFunc(func(sluice.Message) error { return errors.New("dial tcp: connection refused") }),
	})

	// Strand it (transient failure), then the work sender is removed from config.
	_, err = svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { return nil }),
	})

	out, err := svc.ReSend(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusApproved), out.Status, "refused re-send stays approved")
	assert.NotEmpty(t, out.Warn)
}

// C4: re-send only acts on an approved message with a recorded send error; a
// pending or already-sent message is refused with ErrNotResendable.
func TestReSendRejectsNonResendable(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: a@x.test\r\n\r\nb\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { return nil }),
	})

	// Pending → not resendable.
	_, err = svc.ReSend(context.Background(), m.ID)
	assert.ErrorIs(t, err, admin.ErrNotResendable)

	// Clean approve → sent → not resendable.
	_, err = svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	_, err = svc.ReSend(context.Background(), m.ID)
	assert.ErrorIs(t, err, admin.ErrNotResendable)
}

// ApproveAs sends via the chosen inbox's sender, rewrites both the envelope and
// the header From to that inbox's identity, and leaves the stored record as
// submitted (ADR 0023 slice 5).
func TestApproveAsSendsFromChosenIdentity(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "assistant@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: assistant@x.test\r\nTo: d@y.test\r\nSubject: hi\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	var sentVia string
	var sent sluice.Message
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(msg sluice.Message) error { sentVia = "default"; sent = msg; return nil }),
		"work":               senderFunc(func(msg sluice.Message) error { sentVia = "work"; sent = msg; return nil }),
	})
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "default@x.test", "work": "work@x.test"})

	out, err := svc.ApproveAs(context.Background(), m.ID, "work")
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	assert.Equal(t, "work", sentVia, "sent via the chosen inbox's sender")
	assert.Equal(t, "work@x.test", sent.From, "envelope MAIL FROM rewritten to the chosen identity")
	assert.Contains(t, string(sent.Released), "From: work@x.test", "header From rewritten in the sent body")
	assert.NotContains(t, string(sent.Released), "assistant@x.test")

	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, "assistant@x.test", stored.From, "the stored record keeps the original From (send-time rewrite only)")
}

func TestApproveAsUnknownInbox(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", From: "a@x.test", Rcpt: []string{"d@y.test"}, Raw: []byte("From: a@x.test\r\n\r\nb\r\n")})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "d@x.test"})

	_, err = svc.ApproveAs(context.Background(), m.ID, "nope")
	assert.ErrorIs(t, err, admin.ErrUnknownInbox)

	// C5: the failed ApproveAs must not have committed the approve verdict — the
	// message stays pending and re-approvable, never stranded in `approved` with
	// no send attempted.
	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, stored.Status, "unknown-inbox ApproveAs must leave the message pending")

	// And a plain approve still works afterwards (the strand would have made this
	// fail with ErrNotPending). The default StubSender leaves it `approved` (no real
	// upstream), which is the un-stranded success we care about here.
	out, err := svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	assert.NotEqual(t, sluice.StatusPending, sluice.Status(out.Status), "re-approve must move the message off pending")
	assert.NotErrorIs(t, err, sluice.ErrNotPending)
}

// C5: when the rewrite fails (a malformed header block that textproto cannot
// parse) the approve verdict must not commit — the message stays pending.
func TestApproveAsRewriteFailureStaysPending(t *testing.T) {
	q, _ := seedStore(t)
	// A header line with no colon is not a valid field; textproto.ReadHeader
	// rejects it, so rewriteFrom fails.
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("this-is-not-a-header\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetInboxIdentities(map[string]string{"work": "work@x.test"})

	_, err = svc.ApproveAs(context.Background(), m.ID, "work")
	require.Error(t, err)

	stored, err := q.Get(m.ID)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusPending, stored.Status, "rewrite-failure ApproveAs must leave the message pending")
}

// Inboxes lists only inboxes with a non-empty identity, sorted by name.
func TestInboxesList(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	svc.SetInboxIdentities(map[string]string{"work": "w@x.test", "default": "d@x.test", "recv-only": ""})

	got := svc.Inboxes()
	require.Len(t, got, 2, "only inboxes with a send identity")
	assert.Equal(t, "default", got[0].Name)
	assert.Equal(t, "work", got[1].Name)
}

// GET /inboxes and POST /queue/{id}/approve-as/{inbox} round-trip through the
// client → server → service (ADR 0023 slice 5).
func TestChangeSenderRoundtrip(t *testing.T) {
	q, _ := seedStore(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", From: "assistant@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: assistant@x.test\r\nTo: d@y.test\r\n\r\nbody\r\n"),
	})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	var sentVia string
	svc.SetSenders(map[string]backend.Sender{
		inbound.DefaultInbox: senderFunc(func(sluice.Message) error { sentVia = "default"; return nil }),
		"work":               senderFunc(func(sluice.Message) error { sentVia = "work"; return nil }),
	})
	svc.SetInboxIdentities(map[string]string{inbound.DefaultInbox: "default@x.test", "work": "work@x.test"})
	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	ids, err := c.Inboxes(ctx)
	require.NoError(t, err)
	require.Len(t, ids, 2)

	out, err := c.ApproveAs(ctx, m.ID, "work")
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	assert.Equal(t, "work", sentVia)
}
