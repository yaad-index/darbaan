// Package inboxcfg is the configuration schema for ADR 0023 multi-inbox: a named
// list of inboxes, each with its own backend (ADR 0009), send identity, and
// {default_visibility, rules} policy unit (ADR 0022). It parses the `inboxes:`
// section and resolves the back-compat default — a config with no `inboxes:` is
// one implicit "default" inbox built from the legacy top-level fields, so an
// existing single-inbox deployment is unchanged.
//
// This increment is schema + validation only; wiring per-inbox sync / store /
// filter / outbound routing onto these definitions lands in the later
// increments. The single agent (ADR 0010) addresses each inbox by name.
package inboxcfg

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/filter"
)

// Inbox is one configured mailbox the single agent addresses by name (ADR 0023).
type Inbox struct {
	Name     string  `yaml:"name"`
	Identity string  `yaml:"identity"` // the From/envelope identity Darbaan sends as for this inbox
	Backend  Backend `yaml:"backend"`

	// The per-inbox filter policy unit (ADR 0021/0022): EITHER inline
	// default_visibility + rules (captured as raw YAML so it compiles through the
	// existing filter engine without re-exporting its config), OR a filter_file
	// path to a YAML rules file. The two are mutually exclusive (a fail-fast config
	// error if both are set). filter_file eases collapsing an existing path-based
	// deployment into an inboxes: entry (ADR 0023).
	DefaultVisibility string    `yaml:"default_visibility"`
	Rules             yaml.Node `yaml:"rules"`
	FilterFile        string    `yaml:"filter_file"`
}

// Backend is an inbox's upstream account coordinates (ADR 0009). Secrets
// (passwords) are supplied out-of-band via env/secret, never in config
// (ADR 0012), so they are not fields here.
type Backend struct {
	IMAPHost     string `yaml:"imap_host"`
	IMAPUsername string `yaml:"imap_username"`
	IMAPMailbox  string `yaml:"imap_mailbox"`
	MaxAge       string `yaml:"max_age"`
	SenderType   string `yaml:"sender_type"`
	SMTPHost     string `yaml:"smtp_host"`
	SMTPUsername string `yaml:"smtp_username"`
}

type fileConfig struct {
	Inboxes []Inbox `yaml:"inboxes"`
}

// Parse reads the `inboxes:` list from a config document. An absent or empty
// `inboxes:` yields nil — the caller substitutes the implicit default via
// Resolve.
func Parse(data []byte) ([]Inbox, error) {
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("inboxcfg: parse: %w", err)
	}
	return fc.Inboxes, nil
}

// Resolve returns the configured inboxes, or a single implicit inbox when none
// are configured — the back-compat path so a legacy single-inbox config keeps
// working unchanged (ADR 0023). implicit is built by the caller from the legacy
// top-level fields.
func Resolve(parsed []Inbox, implicit Inbox) []Inbox {
	if len(parsed) == 0 {
		return []Inbox{implicit}
	}
	return parsed
}

// Validate checks an inbox list: at least one inbox, unique non-empty names, and
// each inbox's filter compiles. Identity is not required here — an inbox may be
// receive-only; outbound identity matching is enforced where mail is sent.
func Validate(inboxes []Inbox) error {
	if len(inboxes) == 0 {
		return fmt.Errorf("inboxcfg: no inboxes configured")
	}
	seen := make(map[string]bool, len(inboxes))
	envSeen := make(map[string]string, len(inboxes)) // EnvPrefix → first inbox name
	for i, in := range inboxes {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return fmt.Errorf("inboxcfg: inbox %d: name is required", i+1)
		}
		if seen[name] {
			return fmt.Errorf("inboxcfg: duplicate inbox name %q", name)
		}
		seen[name] = true
		// The per-inbox secret env binding is many-to-one (e.g. "work-1" and
		// "work.1" both mangle to WORK_1), so a collision would silently share
		// secrets — reject it at load (ADR 0023).
		ep := EnvPrefix(name)
		if other, dup := envSeen[ep]; dup {
			return fmt.Errorf("inboxcfg: inboxes %q and %q map to the same secret env prefix %q", other, name, ep)
		}
		envSeen[ep] = name
		if _, err := in.Filter(); err != nil {
			return fmt.Errorf("inboxcfg: inbox %q: %w", name, err)
		}
	}
	return nil
}

// EnvPrefix mangles an inbox name into the infix of its per-inbox secret env vars
// (ADR 0012/0023): uppercased, with every rune outside [A-Z0-9] replaced by '_'
// (e.g. "work" → "WORK", "team-1" → "TEAM_1"). It is the SINGLE source of truth
// for the mangle — both the runtime secret lookup
// (DARBAAN_INBOX_<EnvPrefix>_IMAP_PASSWORD / _SMTP_PASSWORD) and Validate's
// collision guard call it, so they can never diverge. The mangle is many-to-one,
// which is why Validate rejects names that collide on it.
func EnvPrefix(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Route resolves which inbox an outbound submission's From belongs to (ADR 0023):
// the inbox whose Identity equals from (exact RFC5321 address match, case-
// insensitive); else the inbox named defaultName if one is configured (catch-all,
// From not rewritten — preserves N=1/legacy behavior); else ("", false), which the
// caller rejects at submit. So N=1 (an implicit default) accepts any From, and a
// multi-inbox config with no default rejects an unmatched From.
func Route(inboxes []Inbox, from, defaultName string) (string, bool) {
	want := strings.ToLower(strings.TrimSpace(from))
	hasDefault := false
	for _, in := range inboxes {
		if in.Name == defaultName {
			hasDefault = true
		}
		if id := strings.ToLower(strings.TrimSpace(in.Identity)); id != "" && id == want {
			return in.Name, true
		}
	}
	if hasDefault {
		return defaultName, true
	}
	return "", false
}

// Filter compiles the inbox's filter (ADR 0021/0022): from the filter_file path
// if set, else from the inline {default_visibility, rules}. The two are mutually
// exclusive — both set is a config error. An inbox with neither yields a
// pass-through (default-allow) filter.
func (in Inbox) Filter() (*filter.Filter, error) {
	doc := map[string]any{}
	if in.DefaultVisibility != "" {
		doc["default_visibility"] = in.DefaultVisibility
	}
	if !in.Rules.IsZero() {
		doc["rules"] = &in.Rules
	}
	if in.FilterFile != "" {
		if len(doc) > 0 {
			return nil, fmt.Errorf("filter_file and inline default_visibility/rules are mutually exclusive")
		}
		return filter.Load(in.FilterFile)
	}
	if len(doc) == 0 {
		return filter.Compile(nil)
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal filter: %w", err)
	}
	return filter.Compile(b)
}
