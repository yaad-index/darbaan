package listener

import "crypto/subtle"

// Principal is an authenticated agent identity: the Darbaan login it presents
// (ADR 0002 — the agent never holds upstream credentials). The grants that gate a
// principal's access are added to the session in a later increment (ADR 0027);
// this increment establishes identity and per-agent authentication.
type Principal struct {
	Name     string
	Password string
}

// Auth resolves a presented (username, password) to a configured Principal. The
// password comparison is constant-time, and an unknown username still runs a
// comparison against a fixed value, so authentication fails identically whether
// the username or the password was wrong — no username-enumeration oracle
// (ADR 0027). v1 ran a single credential; this generalizes it to a map of agents.
type Auth struct {
	byName map[string]Principal
}

// dummyPassword equalizes the compare path for an unknown username.
const dummyPassword = "x-darbaan-no-such-principal"

// NewAuth builds an Auth over the given principals, keyed by name. Name
// uniqueness is validated upstream (agentcfg.Validate).
func NewAuth(principals []Principal) *Auth {
	byName := make(map[string]Principal, len(principals))
	for _, p := range principals {
		byName[p.Name] = p
	}
	return &Auth{byName: byName}
}

// SingleAuth builds an Auth for one principal — the back-compat implicit agent
// and the single-agent path.
func SingleAuth(name, password string) *Auth {
	return NewAuth([]Principal{{Name: name, Password: password}})
}

// Verify authenticates a presented (username, password), returning the matched
// principal's name; ok is false on any miss.
func (a *Auth) Verify(username, password string) (name string, ok bool) {
	p, found := a.byName[username]
	if !found {
		// Compare against a fixed value so an unknown username takes a similar path
		// to a wrong password (no username-enumeration oracle).
		subtle.ConstantTimeCompare([]byte(password), []byte(dummyPassword))
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(p.Password)) != 1 {
		return "", false
	}
	return p.Name, true
}
