package telemetry_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
	"github.com/yaad-index/darbaan/internal/telemetry"
	"github.com/yaad-index/darbaan/internal/telemetry/telemetrytest"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestErrorKind(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("aborted: %w", context.DeadlineExceeded), telemetry.KindTimeout},
		{fmt.Errorf("aborted: %w", context.Canceled), telemetry.KindCanceled},
		{fmt.Errorf("backend: send: %w", &smtp.SMTPError{Code: 421, Message: "words-in-a-reply"}), telemetry.Kind4xx},
		{fmt.Errorf("backend: auth: %w", &smtp.SMTPError{Code: 535, Message: "words-in-a-reply"}), telemetry.Kind5xx},
		{fmt.Errorf("imapsync: connect: %w", &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAuthenticationFailed}), telemetry.KindAuth},
		{fmt.Errorf("imapsync: select: %w", &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent}), telemetry.KindProtocol},
		{fmt.Errorf("backend: dial: %w", x509.UnknownAuthorityError{}), telemetry.KindTLS},
		{fmt.Errorf("backend: dial: %w", tls.RecordHeaderError{}), telemetry.KindTLS},
		{fmt.Errorf("backend: dial: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")}), telemetry.KindDial},
		{fmt.Errorf("imapsync: fetch: %w", &net.OpError{Op: "read", Err: timeoutErr{}}), telemetry.KindTimeout},
		{errors.New("words-in-an-error"), telemetry.KindOther},
	} {
		assert.Equal(t, tc.want, telemetry.ErrorKind(tc.err), "%v", tc.err)
	}
}

func TestTheApprovalChainIsCounted(t *testing.T) {
	m, collect := telemetrytest.New(t)
	ctx := context.Background()
	m.Outbound(ctx, telemetry.Queued)
	m.Outbound(ctx, telemetry.Approved)
	m.Send(ctx, 2*time.Second, nil)
	m.Send(ctx, time.Second, fmt.Errorf("backend: send: %w", &smtp.SMTPError{Code: 550, Message: "words-in-a-reply"}))
	m.Send(ctx, 3*time.Second, fmt.Errorf("backend: send: %w: %w", sluice.ErrOutcomeUnknown, net.ErrClosed))
	m.HoldDecision(ctx, telemetry.Exposed)
	m.HoldDecision(ctx, telemetry.Dropped)

	got := collect()
	assert.Equal(t, "{message}", got["darbaan.outbound.messages"].Unit)
	assert.ElementsMatch(t, []telemetrytest.Point{
		{Attrs: map[string]string{"darbaan.outbound.event": "queued"}, Value: 1},
		{Attrs: map[string]string{"darbaan.outbound.event": "approved"}, Value: 1},
		{Attrs: map[string]string{"darbaan.outbound.event": "sent"}, Value: 1},
		{Attrs: map[string]string{"darbaan.outbound.event": "send_failed", "error.type": "5xx"}, Value: 1},
		{Attrs: map[string]string{"darbaan.outbound.event": "outcome_unknown"}, Value: 1},
	}, got["darbaan.outbound.messages"].Points)

	send := got["darbaan.send.duration"]
	assert.Equal(t, "s", send.Unit)
	assert.Equal(t, telemetry.DurationBuckets, send.Bounds)
	assert.ElementsMatch(t, []telemetrytest.Point{
		{Attrs: map[string]string{"darbaan.outcome": "ok"}, Value: 1, Sum: 2},
		{Attrs: map[string]string{"darbaan.outcome": "failed", "error.type": "5xx"}, Value: 1, Sum: 1},
		{Attrs: map[string]string{"darbaan.outcome": "unknown"}, Value: 1, Sum: 3},
	}, send.Points)

	assert.ElementsMatch(t, []telemetrytest.Point{
		{Attrs: map[string]string{"darbaan.hold.decision": "exposed"}, Value: 1},
		{Attrs: map[string]string{"darbaan.hold.decision": "dropped"}, Value: 1},
	}, got["darbaan.inbound.hold_decisions"].Points)
}

func TestSyncRunsAreCountedAndTimed(t *testing.T) {
	m, collect := telemetrytest.New(t)
	ctx := context.Background()
	m.SyncRun(ctx, time.Second, nil)
	m.SyncRun(ctx, time.Second, fmt.Errorf("imapsync: connect: %w", &net.OpError{Op: "dial", Err: errors.New("refused")}))

	got := collect()
	want := []telemetrytest.Point{
		{Attrs: map[string]string{"darbaan.outcome": "ok"}, Value: 1},
		{Attrs: map[string]string{"darbaan.outcome": "failed", "error.type": "dial"}, Value: 1},
	}
	assert.ElementsMatch(t, want, got["darbaan.sync.runs"].Points)
	assert.Equal(t, "{run}", got["darbaan.sync.runs"].Unit)
	assert.Equal(t, telemetry.DurationBuckets, got["darbaan.sync.duration"].Bounds)
	assert.Len(t, got["darbaan.sync.duration"].Points, 2)
}

func TestPendingIsObserved(t *testing.T) {
	m, collect := telemetrytest.New(t)
	n := int64(3)
	require.NoError(t, m.ObservePending(func() (int64, error) { return n, nil }))
	assert.Equal(t, []telemetrytest.Point{{Attrs: map[string]string{}, Value: 3}}, collect()["darbaan.outbound.pending"].Points)
	n = 1
	assert.Equal(t, int64(1), collect()["darbaan.outbound.pending"].Points[0].Value)
}

// The server metric carries the route template and the status, never the
// path's id, the Host header or anything else the client chose.
func TestTheServerMetricCarriesTheRouteNotThePath(t *testing.T) {
	m, collect := telemetrytest.New(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /queue/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /queue/{id}/approve", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	h := m.Handler(mux)

	for _, r := range []*http.Request{
		httptest.NewRequest("GET", "http://words-in-a-host.example/queue/id-in-a-path", nil),
		httptest.NewRequest("POST", "http://words-in-a-host.example/queue/id-in-a-path/approve", nil),
		httptest.NewRequest("GET", "http://words-in-a-host.example/no-such-route-in-a-path", nil),
		httptest.NewRequest("WORDS-IN-A-METHOD", "http://words-in-a-host.example/queue/id-in-a-path", nil),
	} {
		h.ServeHTTP(httptest.NewRecorder(), r)
	}

	got := collect()["http.server.request.duration"]
	assert.Equal(t, "s", got.Unit)
	assert.Equal(t, httpBuckets, got.Bounds, "the HTTP conventions' boundaries, as the README says")
	routes := map[string]string{}
	for _, p := range got.Points {
		for k, v := range p.Attrs {
			assert.NotContains(t, v, "-in-a-", "attribute %s", k)
		}
		routes[p.Attrs["http.request.method"]+" "+p.Attrs["http.response.status_code"]] = p.Attrs["http.route"]
	}
	assert.Equal(t, map[string]string{
		"GET 200":    "/queue/{id}",
		"POST 500":   "/queue/{id}/approve",
		"GET 404":    "",
		"_OTHER 405": "",
	}, routes)
	for _, p := range got.Points {
		if p.Attrs["http.response.status_code"] == "500" {
			assert.Equal(t, "500", p.Attrs["error.type"])
		}
	}
}

// The client metric carries the server's host and port and the status, never
// the path: some APIs put a credential in it.
func TestTheClientMetricLeavesOutThePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	m, collect := telemetrytest.New(t)
	c := &http.Client{Transport: m.Transport(nil)}
	resp, err := c.Get(srv.URL + "/botSECRET-IN-A-PATH/getMe?q=words-in-a-query")
	require.NoError(t, err)
	_ = resp.Body.Close()
	_, err = c.Get("http://127.0.0.1:1/unreachable")
	require.Error(t, err)

	got := collect()["http.client.request.duration"]
	require.Len(t, got.Points, 2)
	assert.Equal(t, httpBuckets, got.Bounds)
	for _, p := range got.Points {
		for k, v := range p.Attrs {
			assert.False(t, strings.Contains(v, "SECRET") || strings.Contains(v, "in-a-"), "attribute %s = %q", k, v)
		}
		assert.Equal(t, "127.0.0.1", p.Attrs["server.address"])
	}
	kinds := map[string]bool{}
	for _, p := range got.Points {
		kinds[p.Attrs["http.response.status_code"]+"|"+p.Attrs["error.type"]] = true
	}
	assert.Equal(t, map[string]bool{"200|": true, "|dial": true}, kinds)
}

func TestNilMetricsRecordNothing(t *testing.T) {
	var m *telemetry.Metrics
	ctx := context.Background()
	next := http.NotFoundHandler()
	assert.NotPanics(t, func() {
		m.Outbound(ctx, telemetry.Queued)
		m.Send(ctx, time.Second, nil)
		m.HoldDecision(ctx, telemetry.Exposed)
		m.SyncRun(ctx, time.Second, nil)
		assert.NoError(t, m.ObservePending(func() (int64, error) { return 0, nil }))
		m.Handler(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		assert.Equal(t, http.DefaultTransport, m.Transport(http.DefaultTransport))
	})
}

// httpBuckets are the HTTP conventions' advised boundaries, which the httpconv
// constructors apply.
var httpBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
