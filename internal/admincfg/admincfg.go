// Package admincfg is the admin-API scoped-token config schema (ADR 0029): the
// `admin_clients:` list that sits beside `inboxes:` (ADR 0023) and `agents:`
// (ADR 0027). Each admin client is a named credential with a least-privilege set
// of scopes; its token is supplied out-of-band via env, never in config
// (ADR 0012), and gates only the admin API (ADR 0017) — it is unrelated to the
// ADR 0027 agent grants that gate mail read/send.
//
// A config with no `admin_clients:` list yields the back-compat behavior: the
// single DARBAAN_ADMIN_TOKEN is an implicit full-scope root, so an existing
// single-token deployment is unchanged (opt-in, exactly like `inboxes:`).
//
// This increment is schema + validation + the scope vocabulary and the
// authoritative route→scope map. ENFORCEMENT — resolving a presented token to a
// client and authorizing the route's required scope in the admin auth middleware
// — lands in the next increment; here the schema is parsed and validated, but
// access is not yet gated.
package admincfg

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

// The scope vocabulary (ADR 0029): capability-based, coarse, one required scope
// per admin route. A read scope grants the list/show endpoints of a resource; a
// decide/release scope grants its state-changing endpoints.
const (
	ScopeQueueRead        = "queue:read"
	ScopeQueueDecide      = "queue:decide"
	ScopeHoldsRead        = "holds:read"
	ScopeHoldsDecide      = "holds:decide"
	ScopeReconcileRead    = "reconcile:read"
	ScopeReconcileRelease = "reconcile:release"
	ScopeInboxesRead      = "inboxes:read"
)

// RouteScopes is the authoritative route→required-scope map (ADR 0029): every
// admin route (ADR 0017), keyed by its net/http ServeMux pattern, mapped to the
// single scope a client's token must carry to reach it. The enforcement
// increment registers each route against this map; a test pins it complete and
// consistent (every route present, every value a known scope). Note reconcile
// has read but the Telegram cap-latch alert (#149) reads GET /reconcile — so a
// client needs only reconcile:read for it, never reconcile:release.
var RouteScopes = map[string]string{
	"GET /queue":                          ScopeQueueRead,
	"GET /queue/{id}":                     ScopeQueueRead,
	"POST /queue/{id}/approve":            ScopeQueueDecide,
	"POST /queue/{id}/approve-as/{inbox}": ScopeQueueDecide,
	"POST /queue/{id}/reject":             ScopeQueueDecide,
	"GET /holds":                          ScopeHoldsRead,
	"POST /holds/{id}/expose":             ScopeHoldsDecide,
	"POST /holds/{id}/drop":               ScopeHoldsDecide,
	"GET /reconcile":                      ScopeReconcileRead,
	"POST /reconcile/{inbox}/release":     ScopeReconcileRelease,
	"GET /inboxes":                        ScopeInboxesRead,
}

// allScopes is the set of valid scopes, derived once from the vocabulary.
var allScopes = map[string]bool{
	ScopeQueueRead:        true,
	ScopeQueueDecide:      true,
	ScopeHoldsRead:        true,
	ScopeHoldsDecide:      true,
	ScopeReconcileRead:    true,
	ScopeReconcileRelease: true,
	ScopeInboxesRead:      true,
}

// AllScopes returns every scope in the vocabulary, sorted — the full-scope set an
// implicit or explicit root client is granted.
func AllScopes() []string {
	out := make([]string, 0, len(allScopes))
	for s := range allScopes {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ValidScope reports whether s is a known scope.
func ValidScope(s string) bool { return allScopes[s] }

// Client is one named admin credential (ADR 0029). The token is never a field —
// it is read from the env var named by TokenEnv(Name), per ADR 0012.
type Client struct {
	Name   string   `yaml:"name"`
	Scopes []string `yaml:"scopes"`
}

type fileConfig struct {
	Clients []Client `yaml:"admin_clients"`
}

// Parse reads the `admin_clients:` list from a config document. An absent or
// empty list yields nil — the caller substitutes the implicit full-scope root.
func Parse(data []byte) ([]Client, error) {
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("admincfg: parse: %w", err)
	}
	return fc.Clients, nil
}

// TokenEnv is the env var an admin client's token is read from (ADR 0012):
// DARBAAN_ADMIN_TOKEN_<NAME>, where <NAME> is mangled by the shared
// inboxcfg.EnvPrefix rule (uppercased, every rune outside [A-Z0-9] → '_'). It is
// the single source of truth for the mangle; Validate's collision guard calls it,
// so a runtime lookup and the load-time check can never diverge. The mangle is
// many-to-one, which is why Validate rejects client names that collide on it.
func TokenEnv(name string) string {
	return "DARBAAN_ADMIN_TOKEN_" + inboxcfg.EnvPrefix(name)
}

// HasScope reports whether the client is granted scope.
func (c Client) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Validate checks an admin-client list: unique names, unique token-env names (the
// many-to-one mangle must not silently share a token), and, per client, a
// non-empty scope set drawn from the known vocabulary with no duplicates
// (ADR 0029).
func Validate(clients []Client) error {
	if len(clients) == 0 {
		return fmt.Errorf("admincfg: no admin clients configured")
	}
	seen := make(map[string]bool, len(clients))
	envSeen := make(map[string]string, len(clients)) // token-env → first client name
	for i, c := range clients {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("admincfg: admin client %d: name is required", i+1)
		}
		if seen[name] {
			return fmt.Errorf("admincfg: duplicate admin client name %q", name)
		}
		seen[name] = true
		// The token env binding is many-to-one (e.g. "a-b" and "a_b" both mangle to
		// DARBAAN_ADMIN_TOKEN_A_B), so a collision would silently share one token —
		// reject it at load (ADR 0029).
		env := TokenEnv(name)
		if other, dup := envSeen[env]; dup {
			return fmt.Errorf("admincfg: admin clients %q and %q map to the same token env %q", other, name, env)
		}
		envSeen[env] = name
		if err := validateScopes(name, c.Scopes); err != nil {
			return err
		}
	}
	return nil
}

// validateScopes checks one client's scope set: non-empty, each scope known and
// granted at most once.
func validateScopes(client string, scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("admincfg: admin client %q: at least one scope is required", client)
	}
	scopeSeen := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		if !ValidScope(s) {
			return fmt.Errorf("admincfg: admin client %q: unknown scope %q (want one of %s)", client, s, strings.Join(AllScopes(), ", "))
		}
		if scopeSeen[s] {
			return fmt.Errorf("admincfg: admin client %q: repeats scope %q", client, s)
		}
		scopeSeen[s] = true
	}
	return nil
}
