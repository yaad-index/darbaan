package admincfg_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admincfg"
)

func TestParse(t *testing.T) {
	doc := []byte(`
admin_clients:
  - name: telegram
    scopes: [queue:read, queue:decide, holds:read, holds:decide, reconcile:read]
  - name: pre-screener
    scopes: [queue:read, holds:read]
`)
	clients, err := admincfg.Parse(doc)
	require.NoError(t, err)
	require.Len(t, clients, 2)
	assert.Equal(t, "telegram", clients[0].Name)
	assert.True(t, clients[0].HasScope(admincfg.ScopeReconcileRead))
	assert.False(t, clients[0].HasScope(admincfg.ScopeReconcileRelease))
	assert.True(t, clients[1].HasScope(admincfg.ScopeQueueRead))
	assert.False(t, clients[1].HasScope(admincfg.ScopeQueueDecide), "read-only client has no decide")
}

// No admin_clients: yields nil — the caller substitutes the implicit full-scope
// root (back-compat).
func TestParseEmpty(t *testing.T) {
	clients, err := admincfg.Parse([]byte("inboxes:\n  - name: default\n"))
	require.NoError(t, err)
	assert.Nil(t, clients)
}

func TestTokenEnv(t *testing.T) {
	assert.Equal(t, "DARBAAN_ADMIN_TOKEN_TELEGRAM", admincfg.TokenEnv("telegram"))
	assert.Equal(t, "DARBAAN_ADMIN_TOKEN_PRE_SCREENER", admincfg.TokenEnv("pre-screener"))
}

func TestValidate(t *testing.T) {
	ok := []admincfg.Client{
		{Name: "telegram", Scopes: []string{admincfg.ScopeQueueDecide}},
		{Name: "cli", Scopes: admincfg.AllScopes()},
	}
	assert.NoError(t, admincfg.Validate(ok))

	assert.Error(t, admincfg.Validate(nil), "empty list is rejected (caller uses the implicit root instead)")

	dupName := []admincfg.Client{
		{Name: "a", Scopes: []string{admincfg.ScopeQueueRead}},
		{Name: "a", Scopes: []string{admincfg.ScopeHoldsRead}},
	}
	assert.Error(t, admincfg.Validate(dupName), "duplicate name")

	// "a-b" and "a_b" both mangle to the same token env → silently shared token.
	envCollision := []admincfg.Client{
		{Name: "a-b", Scopes: []string{admincfg.ScopeQueueRead}},
		{Name: "a_b", Scopes: []string{admincfg.ScopeHoldsRead}},
	}
	assert.Error(t, admincfg.Validate(envCollision), "token-env collision")

	assert.Error(t, admincfg.Validate([]admincfg.Client{{Name: "x"}}), "empty scope set")
	assert.Error(t, admincfg.Validate([]admincfg.Client{{Name: "x", Scopes: []string{"queue:write"}}}), "unknown scope")
	assert.Error(t, admincfg.Validate([]admincfg.Client{{Name: "x", Scopes: []string{admincfg.ScopeQueueRead, admincfg.ScopeQueueRead}}}), "duplicate scope")
	assert.Error(t, admincfg.Validate([]admincfg.Client{{Name: "  ", Scopes: []string{admincfg.ScopeQueueRead}}}), "blank name")
}

func TestAllScopesAndValidScope(t *testing.T) {
	all := admincfg.AllScopes()
	assert.Len(t, all, 8)
	for _, s := range all {
		assert.True(t, admincfg.ValidScope(s))
	}
	assert.False(t, admincfg.ValidScope("queue:write"))
	assert.False(t, admincfg.ValidScope(""))
}

// The route→scope map is complete and consistent: every value is a known scope,
// and it covers exactly the admin routes (ADR 0029). The route set is pinned here
// so a new/removed admin route without a scope binding fails the build's tests.
func TestRouteScopesComplete(t *testing.T) {
	wantRoutes := []string{
		"GET /queue",
		"GET /queue/{id}",
		"POST /queue/{id}/approve",
		"POST /queue/{id}/approve-as/{inbox}",
		"POST /queue/{id}/reject",
		"GET /holds",
		"POST /holds/{id}/expose",
		"POST /holds/{id}/drop",
		"GET /reconcile",
		"POST /reconcile/{inbox}/release",
		"GET /inboxes",
		"GET /sync-status",
	}
	assert.Len(t, admincfg.RouteScopes, len(wantRoutes), "no extra/missing routes")
	for _, r := range wantRoutes {
		scope, ok := admincfg.RouteScopes[r]
		require.True(t, ok, "route %q has a required scope", r)
		assert.True(t, admincfg.ValidScope(scope), "route %q maps to a known scope (%q)", r, scope)
	}
	// The Telegram #149 cap-latch read path needs reconcile:read, not release.
	assert.Equal(t, admincfg.ScopeReconcileRead, admincfg.RouteScopes["GET /reconcile"])
	assert.Equal(t, admincfg.ScopeReconcileRelease, admincfg.RouteScopes["POST /reconcile/{inbox}/release"])
}
