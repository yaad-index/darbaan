package admin_test

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/telemetry/telemetrytest"
)

// Each expose and drop the operator commits is counted by decision (two
// exposes and one drop, so the two cannot be swapped unseen); one the store
// refuses (an unknown id) is not.
func TestHoldDecisionsAreCounted(t *testing.T) {
	q, _ := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	flt, err := filter.Compile([]byte("rules: [{match: [{field: label, op: equals, value: review}], action: hold-for-human}]"))
	require.NoError(t, err)
	svc.SetInboundHolds(map[string]*filter.Filter{inbound.DefaultInbox: flt}, func(string) string { return "agent" }, nil, false)
	m, collect := telemetrytest.New(t)
	svc.SetMetrics(m)

	_, a, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	_, b, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 2, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	_, c, err := inbox.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 3, UIDValidity: 1, Keywords: []string{"review"}})
	require.NoError(t, err)
	_, err = svc.ExposeHeld(context.Background(), a.ID)
	require.NoError(t, err)
	_, err = svc.ExposeHeld(context.Background(), c.ID)
	require.NoError(t, err)
	_, err = svc.DropHeld(context.Background(), b.ID)
	require.NoError(t, err)
	_, err = svc.DropHeld(context.Background(), "no-such-id")
	require.Error(t, err)

	counts := map[string]int64{}
	for _, p := range collect()["darbaan.inbound.hold_decisions"].Points {
		counts[p.Attrs["darbaan.hold.decision"]] = p.Value
	}
	assert.Equal(t, map[string]int64{"exposed": 2, "dropped": 1}, counts)
}

// An instrumented API records its requests under their route templates.
func TestTheAPIIsInstrumented(t *testing.T) {
	q, _ := seedStore(t)
	svc := admin.NewService(q, newInbound(t), backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	srv, err := admin.NewServer("127.0.0.1:0", "tok", svc)
	require.NoError(t, err)
	m, collect := telemetrytest.New(t)
	srv.Instrument(m)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	req, err := http.NewRequest("GET", "http://"+l.Addr().String()+"/queue/some-id", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	points := collect()["http.server.request.duration"].Points
	require.Len(t, points, 1)
	assert.Equal(t, "/queue/{id}", points[0].Attrs["http.route"])
	assert.Equal(t, "GET", points[0].Attrs["http.request.method"])
	assert.Equal(t, strconv.Itoa(resp.StatusCode), points[0].Attrs["http.response.status_code"])
}
