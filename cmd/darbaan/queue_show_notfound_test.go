package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `queue show` is what the outbound fetch-failure card tells the operator to run, and
// the card says a not-found reply means the decision is already made — take no
// action. So the wording must be reachable ONLY from this service's signal (#260).

// A 404 carrying the service's marker: name the already-made decision.
func TestQueueShowNotFoundNamesTheDecisionAsMade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"admin: message is not in the outbound queue","code":"not_found"}`))
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&QueueShowCmd{ID: "gone"}).Run(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer in the outbound queue")
	assert.Contains(t, err.Error(), "take no action")
}

// 🚨 The case the marker exists for: a bare 404 from a route-less or mis-pointed peer
// must NOT reach the take-no-action wording, even though its status text contains the
// words "not found". It is a tool fault about a message that may well be live.
func TestQueueShowBareNotFoundDoesNotSteerToTakeNoAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&QueueShowCmd{ID: "live"}).Run(cli)
	require.Error(t, err, "it is still an error — just not one about the message")
	assert.NotContains(t, err.Error(), "no longer in the outbound queue",
		"a stranger's 404 must not be rendered as a decision about this id")
	assert.NotContains(t, err.Error(), "take no action",
		"and must not steer the operator away from looking again")
	assert.Contains(t, strings.ToLower(err.Error()), "not found",
		"the raw status still says 'not found' — which is exactly why the wording cannot key on it")
}
