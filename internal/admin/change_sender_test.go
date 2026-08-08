package admin_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

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
