package listener

import "crypto/subtle"

// Principal is an authenticated agent (ADR 0002 — the agent never holds upstream
// credentials): its Darbaan login plus the grants that gate its access (ADR 0027).
// DefaultInbox is the inbox this agent sees as IMAP INBOX; Reads/Sends are the
// inboxes it may read / send as. A principal with nil Reads/Sends is unrestricted
// — the single-agent / back-compat case, where the one agent sees every inbox.
type Principal struct {
	Name         string
	Password     string
	DefaultInbox string
	Reads        map[string]bool
	Sends        map[string]bool
}

// CanRead reports whether the principal may read the inbox. Nil Reads means
// unrestricted (single-agent / back-compat).
func (p *Principal) CanRead(inbox string) bool {
	return p != nil && (p.Reads == nil || p.Reads[inbox])
}

// CanSend reports whether the principal may send as the inbox. Nil Sends means
// unrestricted (single-agent / back-compat).
func (p *Principal) CanSend(inbox string) bool {
	return p != nil && (p.Sends == nil || p.Sends[inbox])
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
// principal; ok is false on any miss.
func (a *Auth) Verify(username, password string) (*Principal, bool) {
	p, found := a.byName[username]
	if !found {
		// Compare against a fixed value so an unknown username takes a similar path
		// to a wrong password (no username-enumeration oracle).
		subtle.ConstantTimeCompare([]byte(password), []byte(dummyPassword))
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(p.Password)) != 1 {
		return nil, false
	}
	return &p, true
}
