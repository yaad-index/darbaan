package admin_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
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
	svc.SetInboundHolds(flt, "agent", nil, false)
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
