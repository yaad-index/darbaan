package admin_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/admincfg"
	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func startServer(t *testing.T, svc *admin.Service, token string) string {
	t.Helper()
	srv, err := admin.NewServer("", token, svc)
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func newSvc(t *testing.T) (*admin.Service, sluice.MessageStore, string) {
	t.Helper()
	q, id := seedStore(t)
	svc := admin.NewService(q, newInbound(t), fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")
	return svc, q, id
}

func TestServerRequiresToken(t *testing.T) {
	svc, _, _ := newSvc(t)
	_, err := admin.NewServer("127.0.0.1:0", "", svc) // no unauthenticated admin API
	require.Error(t, err)
}

func TestAdminRoundtrip(t *testing.T) {
	svc, q, id := newSvc(t)
	addr := startServer(t, svc, "secret-token")
	c := admin.NewClient(addr, "secret-token")
	ctx := context.Background()

	metas, err := c.List(ctx)
	require.NoError(t, err)
	require.Len(t, metas, 1)

	raw, err := c.Show(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("orig"), raw)

	out, err := c.Approve(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)

	got, _ := q.Get(id)
	assert.Equal(t, sluice.StatusSent, got.Status) // the chain ran in the server
}

// C30: a verdict made through a named scoped client (ADR 0029) audits that
// client's name as the actor — the middleware carries it from the authenticated
// request down to the store's verdict audit row, end to end.
func TestVerdictAuditsActingClientName(t *testing.T) {
	cap := &capturingAudit{}
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "s.db"), cap)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close() })
	m, err := q.Enqueue(sluice.Submission{Agent: "agent", Raw: []byte("orig")})
	require.NoError(t, err)

	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	srv, err := admin.NewServer("", "root-token", svc)
	require.NoError(t, err)
	srv.SetScopedClients([]admin.ScopedClient{{
		Name:   "telegram-bot",
		Token:  "scoped-tok",
		Scopes: []string{admincfg.ScopeQueueRead, admincfg.ScopeQueueDecide},
	}})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, err = admin.NewClient(l.Addr().String(), "scoped-tok").Approve(context.Background(), m.ID)
	require.NoError(t, err)

	var approve *audit.Record
	for i := range cap.records {
		if cap.records[i].Event == "approve" {
			approve = &cap.records[i]
		}
	}
	require.NotNil(t, approve, "the approve verdict was audited")
	assert.Equal(t, "telegram-bot", approve.Actor)
}

func TestAdminUnauthorized(t *testing.T) {
	svc, _, _ := newSvc(t)
	addr := startServer(t, svc, "right-token")
	c := admin.NewClient(addr, "wrong-token")
	_, err := c.List(context.Background())
	require.Error(t, err)
}

func TestAdminRejectViaClient(t *testing.T) {
	q, id := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	addr := startServer(t, svc, "tok")

	out, err := admin.NewClient(addr, "tok").Reject(context.Background(), id, "policy", false)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusRejected), out.Status)
	msgs, _ := inbox.List("agent", inbound.DefaultInbox)
	require.Len(t, msgs, 1) // bounce delivered server-side
}

func TestAdminShowNotFound(t *testing.T) {
	svc, _, _ := newSvc(t)
	addr := startServer(t, svc, "tok")
	_, err := admin.NewClient(addr, "tok").Show(context.Background(), "999")
	require.Error(t, err)
}

func TestHoldsRoundtrip(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")
	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)
	_, held, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Subject: "review me", UpstreamUID: 1, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)

	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	list, err := c.HeldList(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, held.ID, list[0].ID)

	m, err := c.Expose(ctx, held.ID)
	require.NoError(t, err)
	assert.Equal(t, held.ID, m.ID)

	list, err = c.HeldList(ctx)
	require.NoError(t, err)
	assert.Empty(t, list) // decided -> off the queue

	_, err = c.Expose(ctx, "999") // unknown id -> error
	assert.Error(t, err)
}

// TestHeldContentErrorsDistinguishUnreachableFromUnreadable pins the premise the
// Telegram fetch-failure guidance (C14/C46) rests on: the operator is told to tell
// "could not reach darbaan" (the tool — reconnect and look again) apart from "could
// not read the message" (the body is unavailable — decide from metadata). That only
// works if the two failure classes are distinguishable in the client's errors.
func TestHeldContentErrorsDistinguishUnreachableFromUnreadable(t *testing.T) {
	// Unreachable: nothing is listening, so the transport fails and the error names
	// the connection.
	_, err := admin.NewClient("127.0.0.1:1", "t").HeldContent(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "darbaan serve", "an unreachable daemon points at the connection")

	// Reachable but the request is rejected (wrong token): a server error, not a
	// transport one, so it must NOT carry the connect hint — else the operator can't
	// tell the tool failing from the message being unreadable.
	svc, _, _ := newSvc(t)
	addr := startServer(t, svc, "right-token")
	_, err = admin.NewClient(addr, "wrong-token").HeldContent(context.Background(), "x")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "darbaan serve", "a reached-but-rejected request is not a connection failure")
}
