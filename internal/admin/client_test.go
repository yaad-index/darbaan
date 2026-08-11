package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// Message ids and inbox names are caller-supplied and can carry URL-significant
// characters. The client url.PathEscape's every id/inbox segment so it stays a
// single path segment rather than altering the route or spilling into a query or
// fragment. This exercises the whole family of endpoints (both prefixes, both the
// id and inbox parameters) — not one — because the escape must be applied to every
// sibling, not most of them: an id like "msg/42?a=b&c=d#frag" round-trips to the
// server's decoded PathValue only if it was escaped on the way out.
//
// The sample includes "/" deliberately: it is the one character whose mishandling
// changes routing rather than a parameter value (an unescaped slash splits into an
// extra path segment and lands on a different route or none). Escaped to %2F it
// stays within one wildcard segment and the mux decodes it back, so the round-trip
// demonstrates the strongest case rather than asserting it.
func TestClientEscapesPathSegments(t *testing.T) {
	const weirdID = "msg/42?a=b&c=d#frag"
	const weirdInbox = "team/inbox+x?y"

	var gotID, gotInbox string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /queue/{id}", func(w http.ResponseWriter, r *http.Request) {
		gotID = r.PathValue("id")
		_, _ = w.Write([]byte("raw"))
	})
	mux.HandleFunc("GET /holds/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		gotID = r.PathValue("id")
		_, _ = w.Write([]byte("body"))
	})
	mux.HandleFunc("POST /holds/{id}/expose", func(w http.ResponseWriter, r *http.Request) {
		gotID = r.PathValue("id")
		_ = json.NewEncoder(w).Encode(inbound.Message{})
	})
	mux.HandleFunc("POST /queue/{id}/approve-as/{inbox}", func(w http.ResponseWriter, r *http.Request) {
		gotID, gotInbox = r.PathValue("id"), r.PathValue("inbox")
		_ = json.NewEncoder(w).Encode(admin.Outcome{})
	})
	mux.HandleFunc("POST /reconcile/{inbox}/release", func(w http.ResponseWriter, r *http.Request) {
		gotInbox = r.PathValue("inbox")
		_ = json.NewEncoder(w).Encode(admin.ReconcileReleaseResult{})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := admin.NewClient(strings.TrimPrefix(ts.URL, "http://"), "tok")
	ctx := context.Background()

	t.Run("Show id segment", func(t *testing.T) {
		gotID = ""
		_, err := c.Show(ctx, weirdID)
		require.NoError(t, err)
		assert.Equal(t, weirdID, gotID)
	})
	t.Run("HeldContent id segment", func(t *testing.T) {
		gotID = ""
		_, err := c.HeldContent(ctx, weirdID)
		require.NoError(t, err)
		assert.Equal(t, weirdID, gotID)
	})
	t.Run("Expose id segment", func(t *testing.T) {
		gotID = ""
		_, err := c.Expose(ctx, weirdID)
		require.NoError(t, err)
		assert.Equal(t, weirdID, gotID)
	})
	t.Run("ApproveAs id and inbox segments", func(t *testing.T) {
		gotID, gotInbox = "", ""
		_, err := c.ApproveAs(ctx, weirdID, weirdInbox)
		require.NoError(t, err)
		assert.Equal(t, weirdID, gotID)
		assert.Equal(t, weirdInbox, gotInbox)
	})
	t.Run("ReleaseReconcile inbox segment", func(t *testing.T) {
		gotInbox = ""
		_, err := c.ReleaseReconcile(ctx, weirdInbox)
		require.NoError(t, err)
		assert.Equal(t, weirdInbox, gotInbox)
	})
}
