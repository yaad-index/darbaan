package admin_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

// TestHeldContentDistinguishesNotHeldFromEmptyBody pins the premise the Telegram
// fetch-failure guidance (C14/C46) and the `holds show` retry rest on: HeldContent's
// three outcomes are distinct through service→http→client, because they call for
// opposite operator actions. Not-currently-held is the typed ErrNotHeld (take no
// action — the decision is already made); held-with-no-stored-body is empty bytes and
// NO error (positive evidence the body is unavailable — decide from metadata); an
// unreachable daemon carries the connect hint (the tool — reconnect and look again).
func TestHeldContentDistinguishesNotHeldFromEmptyBody(t *testing.T) {
	// Unreachable: nothing is listening, so the transport fails and the error names
	// the connection — the operator is told to reconnect and look again, not to decide.
	_, err := admin.NewClient("127.0.0.1:1", "t").HeldContent(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "darbaan serve", "an unreachable daemon points at the connection")

	// Reachable. Seed one held message that has a stored body (present, assessment-held)
	// and one held with no stored body yet (pending, filter-held); everything else is
	// not held.
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")
	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)
	_, withBody, err := inbox.AddSyncedAssessed(
		inbound.Delivery{Owner: "agent", Subject: "has body", Raw: []byte("the body"), UpstreamUID: 1, UIDValidity: 1},
		&inbound.Assessment{Disposition: inbound.AssessmentHeld},
	)
	require.NoError(t, err)
	_, noBody, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", Subject: "no body", UpstreamUID: 2, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)

	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	// Held with a stored body: the body, no error.
	raw, err := c.HeldContent(ctx, withBody.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("the body"), raw)

	// Held with NO stored body: empty bytes and explicitly NOT an error — positive
	// evidence the body is unavailable, which the operator surface reads as "decide
	// from metadata", distinct from the tool failing.
	raw, err = c.HeldContent(ctx, noBody.ID)
	require.NoError(t, err)
	assert.Empty(t, raw)

	// Not currently held (decided, gone, or unknown id): the distinct, errors.Is-able
	// ErrNotHeld — never conflated with an empty body. The operator surface reads it as
	// "the decision is already made, take no action", the opposite of deciding blind.
	_, err = c.HeldContent(ctx, "not-a-held-id")
	require.ErrorIs(t, err, admin.ErrNotHeld)
}

// TestHeldContentMapsNotHeldOnlyOnServiceCode pins that the client maps a 404 to the
// not-held sentinel ONLY on positive evidence — the service's not-held code in the
// body. A bare 404 (a route-less daemon under version skew, or a mis-pointed peer)
// carries no such code and must surface as a generic error routed to the tool branch,
// never as not-held for every id. The client cannot know it is talking to this handler,
// so it must not infer a message-state meaning from a bare status any peer could return.
func TestHeldContentMapsNotHeldOnlyOnServiceCode(t *testing.T) {
	coded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"admin: message is not currently held","code":"not_held"}`))
	}))
	defer coded.Close()
	_, err := admin.NewClient(strings.TrimPrefix(coded.URL, "http://"), "t").HeldContent(context.Background(), "x")
	require.ErrorIs(t, err, admin.ErrNotHeld, "a 404 carrying the service's not-held code maps to the sentinel")

	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // the mux's own bare 404 — no code
	}))
	defer bare.Close()
	_, err = admin.NewClient(strings.TrimPrefix(bare.URL, "http://"), "t").HeldContent(context.Background(), "x")
	require.Error(t, err)
	assert.NotErrorIs(t, err, admin.ErrNotHeld, "a bare 404 from an unidentified peer is not positive evidence of not-held")
}

// TestHeldContentNoInboxIsUnavailable pins the second instance: a service with no
// inbound store is unconfigured — a tool state — so HeldContent returns
// ErrHoldsUnavailable, never ErrNotHeld. An unconfigured daemon must not assert "the
// decision is already made" about an id it cannot see.
func TestHeldContentNoInboxIsUnavailable(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, nil, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	_, err := svc.HeldContent("any")
	require.ErrorIs(t, err, admin.ErrHoldsUnavailable)
	assert.NotErrorIs(t, err, admin.ErrNotHeld, "an unconfigured service must not claim not-held")
}
