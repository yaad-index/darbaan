package admin_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/admincfg"
)

// startScopedServer builds a server with a root token plus zero or more scoped
// clients (ADR 0029).
func startScopedServer(t *testing.T, svc *admin.Service, rootToken string, clients ...admin.ScopedClient) string {
	t.Helper()
	srv, err := admin.NewServer("", rootToken, svc)
	require.NoError(t, err)
	srv.SetScopedClients(clients)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func doReq(t *testing.T, method, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// ADR 0029: a scoped client reaches only its granted routes; the root token
// reaches all; an unrecognized token is 401 and a recognized token lacking the
// route's scope is 403.
func TestScopedEnforcement(t *testing.T) {
	svc, _, id := newSvc(t)
	addr := startScopedServer(t, svc, "root-tok",
		admin.ScopedClient{Name: "reader", Token: "reader-tok", Scopes: []string{admincfg.ScopeQueueRead, admincfg.ScopeHoldsRead}},
	)
	base := "http://" + addr

	// Root token: full-scope — read AND decide both pass the auth layer.
	assert.Equal(t, http.StatusOK, doReq(t, "GET", base+"/queue", "root-tok"))
	st := doReq(t, "POST", base+"/queue/"+id+"/approve", "root-tok")
	assert.NotEqual(t, http.StatusUnauthorized, st, "root is authenticated")
	assert.NotEqual(t, http.StatusForbidden, st, "root has queue:decide")

	// Reader: queue:read grants GET /queue; it lacks queue:decide → 403 on approve,
	// and lacks reconcile:read → 403 on GET /reconcile (scope denied before the
	// handler, so it's 403 not the handler's 503).
	assert.Equal(t, http.StatusOK, doReq(t, "GET", base+"/queue", "reader-tok"))
	assert.Equal(t, http.StatusForbidden, doReq(t, "POST", base+"/queue/"+id+"/approve", "reader-tok"))
	assert.Equal(t, http.StatusForbidden, doReq(t, "GET", base+"/reconcile", "reader-tok"))

	// Unrecognized / missing token → 401 (distinct from the 403 scope denial).
	assert.Equal(t, http.StatusUnauthorized, doReq(t, "GET", base+"/queue", "nope"))
	assert.Equal(t, http.StatusUnauthorized, doReq(t, "GET", base+"/queue", ""))
}

// The single-token deploy (no scoped clients) is unchanged: the root token
// reaches every route (back-compat).
func TestRootTokenFullAccess(t *testing.T) {
	svc, _, id := newSvc(t)
	addr := startScopedServer(t, svc, "only-tok")
	base := "http://" + addr
	for _, r := range []struct{ method, path string }{
		{"GET", "/queue"}, {"GET", "/holds"}, {"GET", "/reconcile"}, {"GET", "/inboxes"},
	} {
		assert.NotEqual(t, http.StatusForbidden, doReq(t, r.method, base+r.path, "only-tok"), "%s %s", r.method, r.path)
		assert.NotEqual(t, http.StatusUnauthorized, doReq(t, r.method, base+r.path, "only-tok"), "%s %s", r.method, r.path)
	}
	assert.NotEqual(t, http.StatusForbidden, doReq(t, "POST", base+"/queue/"+id+"/approve", "only-tok"))
}

// A client whose token is empty (secret not supplied) is skipped, not registered
// as a zero-token credential.
func TestEmptyScopedClientTokenSkipped(t *testing.T) {
	svc, _, _ := newSvc(t)
	addr := startScopedServer(t, svc, "root-tok",
		admin.ScopedClient{Name: "unset", Token: "", Scopes: []string{admincfg.ScopeQueueRead}},
	)
	// An empty Authorization header must not match the skipped empty-token client.
	assert.Equal(t, http.StatusUnauthorized, doReq(t, "GET", "http://"+addr+"/queue", ""))
}

// NewServer registers every route with a scope from admincfg.RouteScopes — a
// missing binding panics (the map↔routes invariant), so a clean build is the
// cross-check.
func TestNewServerScopesEveryRoute(t *testing.T) {
	svc, _, _ := newSvc(t)
	require.NotPanics(t, func() {
		srv, err := admin.NewServer("", "tok", svc)
		require.NoError(t, err)
		_ = srv.Close()
	})
}
