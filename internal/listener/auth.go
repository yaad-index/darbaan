package listener

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// Principal is an authenticated agent (ADR 0002 — the agent never holds upstream
// credentials): its Darbaan login plus the grants that gate its access (ADR 0027).
// DefaultInbox is the inbox this agent sees as IMAP INBOX; Reads/Sends are the
// inboxes it may read / send as. A principal with nil Reads/Sends is unrestricted
// — the single-agent / back-compat case, where the one agent sees every inbox.
type Principal struct {
	Name string
	// Password is input-only: NewAuth/SingleAuth read it to compute the stored
	// credential MAC and it is never populated on a Principal returned by Verify (#266).
	// A verified principal's Password is always empty — empty by design, not a
	// misconfiguration.
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
	byName map[string]storedPrincipal
}

// storedPrincipal is the internal record NewAuth keeps for each agent: the non-secret
// grants plus the fixed-width MAC of the credential (pwMAC). It holds no plaintext
// password, so Verify has none in scope to compare against — a regression to a raw byte
// compare would have to visibly re-add plaintext credential storage, which is reviewable
// rather than invisible to every behavioural test (#266, C31 follow-up). This narrows
// where the plaintext lives; it does not remove it — the caller's Principal slice still
// carries the password (and it arrives via the environment, which the process retains
// for its lifetime regardless), so this is a smaller-surface claim, not "the password is
// gone from memory".
type storedPrincipal struct {
	name         string
	defaultInbox string
	reads        map[string]bool
	sends        map[string]bool
	pwMAC        []byte
}

// dummyPassword equalizes the compare path for an unknown username.
const dummyPassword = "x-darbaan-no-such-principal"

// compareKey keys the credential comparison; it is random per process. The presented
// password is MAC'd in Verify and each stored credential is MAC'd once at construction
// (NewAuth); the two fixed-width digests are compared, so hmac.Equal — which, like any
// constant-time compare, is length-safe only for equal-length inputs — never sees the
// raw password lengths. A keyed MAC (not a bare password hash) is the right primitive
// here: it makes the fixed-width values unpredictable, so an attacker can't precompute
// or correlate them across runs. Generated once; a randomness failure is fatal, because
// the only fallbacks (comparing raw bytes, or an unkeyed hash) would reintroduce the
// length oracle this closes.
var compareKey = mustRandomKey(32)

func mustRandomKey(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("listener: cannot read randomness for the auth compare key: " + err.Error())
	}
	return b
}

// credMAC returns the fixed-width keyed digest used for the constant-time compare.
func credMAC(s string) []byte {
	m := hmac.New(sha256.New, compareKey)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// dummyMAC is the fixed-width digest the not-found path compares against. Like the
// stored credential digests it is precomputed (at package init), so an unknown username
// does exactly the same work as a wrong password — MAC the presented password, one
// fixed-width compare against an already-computed target — with no extra hashing on
// either path for an attacker to time against.
var dummyMAC = credMAC(dummyPassword)

// NewAuth builds an Auth over the given principals, keyed by name. Name
// uniqueness is validated upstream (agentcfg.Validate).
func NewAuth(principals []Principal) *Auth {
	byName := make(map[string]storedPrincipal, len(principals))
	for _, p := range principals {
		// Hash the credential here and keep only the digest; the plaintext p.Password
		// is not stored (#266).
		byName[p.Name] = storedPrincipal{
			name:         p.Name,
			defaultInbox: p.DefaultInbox,
			reads:        p.Reads,
			sends:        p.Sends,
			pwMAC:        credMAC(p.Password),
		}
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
//
// The password comparison is over fixed-width keyed MACs (credMAC), not the raw bytes.
// A constant-time compare is length-safe only for equal-length inputs — it
// short-circuits on a length mismatch — so comparing raw passwords would leak the
// stored password's length, and (against the fixed-length dummy) whether the username
// exists at all. MAC-ing both sides makes lengths uninformative. The stored credential's
// MAC is computed once at construction (NewAuth) and only the presented password is
// MAC'd here. Every outcome does identical work: MAC the presented password (before the
// lookup), one fixed-width compare against a precomputed target MAC — the stored digest
// for a hit, dummyMAC for a miss — so the found and not-found paths are
// indistinguishable, and both return (nil, false), which both callers map to the same
// ErrAuthFailed with no distinguishing log. This surface is keyed by the presented
// username, so unlike the admin credential set (ADR 0029, which scans every credential
// with no early exit to hide which one matched) there is no set membership to conceal
// here — only that a miss is a miss regardless of which half was wrong (ADR 0027).
//
// "Identical work" describes the compare path; the map lookup ahead of it is not
// identical (a hit compares the key it found, a miss need not), leaving a small residue
// — a key comparison plus network jitter. That residue is accepted rather than closed:
// eliminating it would mean scanning every principal, the scan-all pattern this
// username-keyed surface deliberately declines (there is no membership to hide).
func (a *Auth) Verify(username, password string) (*Principal, bool) {
	got := credMAC(password)
	sp, found := a.byName[username]
	if !found {
		// Compare against the precomputed dummy so the not-found path does the same work
		// as a wrong password — no username-existence timing oracle.
		_ = hmac.Equal(got, dummyMAC)
		return nil, false
	}
	if !hmac.Equal(got, sp.pwMAC) {
		return nil, false
	}
	// Rebuild the principal for the caller from the non-secret fields; the plaintext
	// password was discarded at construction and no caller reads Principal.Password.
	return &Principal{
		Name:         sp.name,
		DefaultInbox: sp.defaultInbox,
		Reads:        sp.reads,
		Sends:        sp.sends,
	}, true
}
