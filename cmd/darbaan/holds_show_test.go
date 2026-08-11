package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHoldsShowEmptyBodyIsError: `holds show` must NOT silently succeed when the body
// is empty. HeldContent serves an empty 200 for an id that is no longer held OR held
// with no stored body — two states the transport conflates. Writing zero bytes and
// exiting 0 would read as "the message is empty", the misrepresentation this surface
// exists to prevent, on the class of message where the body is the decision. So the
// empty case is an error naming both states. Reachable straight from the alert's own
// scenario: the fetch-failure notification fires, the operator retries a minute later,
// the hold was decided in between.
func TestHoldsShowEmptyBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // empty 200 — the not-held / no-stored-body contract
	}))
	defer srv.Close()
	t.Setenv("DARBAAN_ADMIN_TOKEN", "t")

	cli := &CLI{AdminAddr: strings.TrimPrefix(srv.URL, "http://")}
	err := (&HoldsShowCmd{ID: "gone"}).Run(cli)
	require.Error(t, err, "an empty body must be an error, not a silent success")
	assert.Contains(t, err.Error(), "no longer held")
	assert.Contains(t, err.Error(), "no stored body")
}
