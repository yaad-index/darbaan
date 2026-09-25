// Package opidentity resolves the operator-identity list (ADR 0034): the set of
// addresses the operator themselves reads. A submission whose every recipient is
// one of these skips the approval hold, because approving it and delivering it
// both end with the same person reading the same bytes.
//
// The list lives in host configuration only. It is deliberately not writable
// through the admin API and not settable by a submitting client: a gate whose
// exemptions the submitter can widen is self-serve rather than default-deny
// (ADR 0003).
//
// What this package does NOT establish, stated because the whole bypass rests on
// it: matching an address does not establish who reads that address. An alias, a
// group address or a server-side forwarding rule satisfies an exact match while
// delivering somewhere else. The operator configuring an identity is asserting
// that they are its only reader, and nothing here can verify that assertion
// (ADR 0034, Boundaries).
package opidentity

import (
	"fmt"
	"net/mail"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/provenance"
)

// List is a resolved operator-identity set. The zero value is a valid, disabled
// list: it matches nothing, so every message is held (ADR 0034 condition 4).
type List struct {
	addrs map[string]struct{}
}

type fileConfig struct {
	OperatorIdentities []string `yaml:"operator_identities"`
}

// Parse reads the `operator_identities:` list from a config document. An absent
// or empty list yields a disabled List — today's behaviour, everything held, so
// no existing deployment changes disposition on upgrade.
//
// Every entry must be an address that can actually match. An entry that cannot
// fails startup rather than being dropped with a warning: under exact matching a
// wildcard or bare-domain entry would load cleanly and never fire, so the
// operator would be shown the feature's absence as its presence. That is the
// same class as a detector whose patterns cannot match (ADR 0035, Fail-safe).
func Parse(data []byte) (List, error) {
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return List{}, fmt.Errorf("opidentity: parse: %w", err)
	}
	return New(fc.OperatorIdentities)
}

// New validates and normalizes raw config entries into a List.
func New(entries []string) (List, error) {
	if len(entries) == 0 {
		return List{}, nil
	}
	addrs := make(map[string]struct{}, len(entries))
	for i, raw := range entries {
		norm, err := validateEntry(raw)
		if err != nil {
			return List{}, fmt.Errorf("opidentity: operator_identities[%d] %q: %w", i, raw, err)
		}
		addrs[norm] = struct{}{}
	}
	return List{addrs: addrs}, nil
}

// validateEntry canonicalizes one configured entry, rejecting anything that
// exact matching could never match.
func validateEntry(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty entry")
	}
	// Reject wildcards explicitly: "*" is a legal atom character in an RFC 5322
	// local part, so mail.ParseAddress accepts "*@example.com" and a naive parse
	// check would pass an entry that can only ever match an address literally
	// containing an asterisk. ADR 0034 condition 1 is exact-address matching with
	// no wildcards, so the intent behind such an entry cannot be honoured.
	if strings.Contains(trimmed, "*") {
		return "", fmt.Errorf("wildcards are not supported: matching is exact on the full address (ADR 0034)")
	}
	addr, err := parseAddress(trimmed)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// parseAddress reduces an address to its canonical RFC 5321 form, discarding any
// display name: `Some Name <a@b.tld>` and a bare `a@b.tld` both reduce to
// `a@b.tld` (ADR 0034 condition 1). Normalization goes through
// provenance.NormalizeAddress so this path cannot drift from the From check and
// the per-sender trust rules, which compare through the same function.
func parseAddress(s string) (string, error) {
	if parsed, err := mail.ParseAddress(s); err == nil {
		if parsed.Address == "" {
			return "", fmt.Errorf("no address")
		}
		return provenance.NormalizeAddress(parsed.Address), nil
	}
	// go-smtp hands over the envelope RCPT TO, which may arrive bracketed and
	// without a display name — a form mail.ParseAddress rejects on its own.
	bare := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "<"), ">")
	parsed, err := mail.ParseAddress(bare)
	if err != nil {
		return "", fmt.Errorf("not a valid address: %w", err)
	}
	return provenance.NormalizeAddress(parsed.Address), nil
}

// Enabled reports whether any operator identity is configured. A disabled list
// holds everything, which is the default.
func (l List) Enabled() bool { return len(l.addrs) > 0 }

// Len reports how many identities are configured. Operators see this at startup,
// so "the feature is on" is observable rather than inferred.
func (l List) Len() int { return len(l.addrs) }

// Match reports whether addr is an operator identity, returning its canonical
// form. Matching is exact on the address and ignores the display name; there is
// no domain matching, no wildcard and no substring.
func (l List) Match(addr string) (string, bool) {
	if !l.Enabled() {
		return "", false
	}
	norm, err := parseAddress(addr)
	if err != nil {
		return "", false
	}
	if _, ok := l.addrs[norm]; !ok {
		return "", false
	}
	return norm, true
}

// AllMatch reports whether EVERY recipient is an operator identity, returning
// the matched canonical addresses in recipient order. A single non-matching
// address makes the whole message ineligible — the caller then holds all of it,
// with no partial send and no splitting by recipient (ADR 0034 condition 2).
//
// An empty recipient list is NOT a match. "Every recipient matches" is
// vacuously true of no recipients, and a naive all-quantifier would therefore
// bypass a message addressed to nobody — the one case where the bypass's
// safety argument ("the same person reads it either way") has no reader in it
// at all.
func (l List) AllMatch(rcpts []string) ([]string, bool) {
	if !l.Enabled() || len(rcpts) == 0 {
		return nil, false
	}
	matched := make([]string, 0, len(rcpts))
	for _, r := range rcpts {
		norm, ok := l.Match(r)
		if !ok {
			return nil, false
		}
		matched = append(matched, norm)
	}
	return matched, true
}
