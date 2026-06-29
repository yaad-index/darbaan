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
	for i, in := range inboxes {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return fmt.Errorf("inboxcfg: inbox %d: name is required", i+1)
		}
		if seen[name] {
			return fmt.Errorf("inboxcfg: duplicate inbox name %q", name)
		}
		seen[name] = true
		if _, err := in.Filter(); err != nil {
			return fmt.Errorf("inboxcfg: inbox %q: %w", name, err)
		}
	}
	return nil
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
