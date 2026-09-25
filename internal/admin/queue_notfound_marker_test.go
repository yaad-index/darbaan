package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
)

// #260: the outbound Show path maps a 404 to the typed not-found ONLY on positive
// evidence that this service produced it. The failure being prevented is an operator
// one: they are told that "not found" means the decision is already made, and a bare
// 404 from a route-less daemon or a mis-pointed admin address renders as "404 Not
// Found" — text that also contains "not found" — about a message that may be live.
func TestShowMapsQueueNotFoundOnlyOnServiceCode(t *testing.T) {
	q, liveID := seedStore(t)
	svc := admin.NewService(q, newInbound(t), fakeSender{nil}, testSigner(t), strictRouter(), "darbaan.test")
	c := admin.NewClient(startServer(t, svc, "tok"), "tok")
	ctx := context.Background()

	// Positive control, through the real service → http → client path: a message that
	// IS in the queue returns its body. Without this, every assertion below is
	// satisfied by a client that can never fetch anything.
	raw, err := c.Show(ctx, liveID)
	require.NoError(t, err, "control: a live message is fetchable")
	require.NotEmpty(t, raw)

	// A genuine not-found from this service: typed, so the operator surface can speak
	// on the daemon's word rather than on a status string.
	_, err = c.Show(ctx, "not-a-queued-id")
	require.ErrorIs(t, err, admin.ErrQueueNotFound)
}

// The marker, not the status code, is what makes the typed error reachable.
func TestShowTypedNotFoundRequiresTheMarker(t *testing.T) {
	coded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"admin: message is not in the outbound queue","code":"not_found"}`))
	}))
	defer coded.Close()
	_, err := admin.NewClient(strings.TrimPrefix(coded.URL, "http://"), "t").Show(context.Background(), "x")
	require.ErrorIs(t, err, admin.ErrQueueNotFound,
		"control: a 404 carrying this service's code DOES map to the sentinel")

	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // the mux's own bare 404 — no code, and a body that does not decode
	}))
	defer bare.Close()
	_, err = admin.NewClient(strings.TrimPrefix(bare.URL, "http://"), "t").Show(context.Background(), "x")
	require.Error(t, err)
	assert.NotErrorIs(t, err, admin.ErrQueueNotFound,
		"a bare 404 from an unidentified peer is not evidence about any message id")

	// A 404 carrying some OTHER service's marker is equally not evidence: the check is
	// on this marker's value, not on the presence of a code field.
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"gateway: no route","code":"no_route"}`))
	}))
	defer foreign.Close()
	_, err = admin.NewClient(strings.TrimPrefix(foreign.URL, "http://"), "t").Show(context.Background(), "x")
	require.Error(t, err)
	assert.NotErrorIs(t, err, admin.ErrQueueNotFound, "a foreign code is not this service's marker")
}
