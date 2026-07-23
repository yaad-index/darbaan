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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/provenance"
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

	// Upstream reconciliation (ADR 0026): when the source drops a synced message
	// (deleted, archived out, or un-labeled out of a label-folder-scoped mailbox),
	// Darbaan retracts its local copy. The upstream is never modified — retraction
	// is local-only. It is OPT-IN and OFF unless ReconcileEnabled is set, so an
	// upgrade never starts retracting on deploy by surprise; the operator turns it
	// on per inbox. ReconcileInterval is the period between reconcile passes — a
	// full UID listing, heavier than the incremental forward poll, so typically
	// longer; empty uses the runtime default. It is only meaningful when enabled.
	ReconcileEnabled  bool   `yaml:"reconcile_enabled"`
	ReconcileInterval string `yaml:"reconcile_interval"`

	// ReconcileCapFraction is the safety-cap fraction (ADR 0026): a reconcile pass
	// that would retract more than this fraction of the inbox's synced set latches
	// (suspends reconciliation, pending an operator release) instead of purging —
	// the anomaly backstop against a source-side mass removal silently emptying the
	// store. Zero uses the runtime default; a set value must be in (0,1].
	ReconcileCapFraction float64 `yaml:"reconcile_cap_fraction"`
	// ReconcileCapFloor is the safety-cap absolute floor: the cap never latches
	// unless at least this many messages would be retracted (so a tiny inbox never
	// false-latches on a normal single removal). Zero uses the runtime default; a
	// set value must be >= 1. The latch rule is the conjunction of both —
	// retract-count >= floor AND retract-count > fraction * synced-set.
	ReconcileCapFloor int `yaml:"reconcile_cap_floor"`

	// On-demand inbound sync (ADR 0028): when set, an IMAP STATUS for this inbox
	// triggers an immediate, debounced upstream pull before the counts are computed,
	// so "give me current status" reflects mail that arrived since the last
	// background poll (ADR 0019) instead of waiting out the interval. It is OPT-IN
	// and OFF unless SyncOnStatus is set — STATUS stays a cheap query by default;
	// NOOP/CHECK never trigger a pull. SyncOnStatusInterval is the debounce window:
	// the minimum gap between on-demand pulls of this inbox (empty uses the runtime
	// default). It is only meaningful when enabled and ignored for an inbox with no
	// upstream syncer.
	SyncOnStatus         bool   `yaml:"sync_on_status"`
	SyncOnStatusInterval string `yaml:"sync_on_status_interval"`

	// Trust/provenance stamping (ADR 0030): the gate stamps X-Darbaan-Trust on
	// this inbox's mail from Trust.Level — anchored on the authenticated source
	// (this inbox), never the From header. An omitted trust block → unknown.
	Trust Trust `yaml:"trust"`
}

// Trust is an inbox's provenance-stamping config (ADR 0030). Only Level is wired
// this slice; Note (slice 3) and BodyBanner (slice 4) are reserved so the config
// schema is stable ahead of those slices.
type Trust struct {
	// Level is the trust the gate stamps for mail from this authenticated source:
	// "trusted" or "untrusted". Omitted (empty) → the message is stamped
	// "unknown" — the fail-safe default a consumer treats as not-safe-to-act.
	Level string `yaml:"level"`
	// Note is a reserved (ADR 0030 slice 3) operator directive templated into
	// X-Darbaan-Note. Validated now (length + no control chars) so the schema is
	// pinned, but not yet stamped.
	Note string `yaml:"note"`
	// BodyBanner is a reserved (ADR 0030 slice 4) toggle for a fenced top-of-body
	// trust banner. Parsed now; not yet acted on.
	BodyBanner bool `yaml:"body_banner"`
	// Rules are per-sender overrides (ADR 0031): the most-specific rule whose
	// matcher matches a message's From supplies the trust level + note, overriding
	// the inbox Level default. Matched on From only (v1); a `trusted` rule is sound
	// only under the upstream-authentication boundary (the README caution).
	Rules []TrustRule `yaml:"rules"`
}

// TrustRule maps a sender to a trust level + optional note (ADR 0031). Exactly
// one matcher is set: From (an exact address, most specific) or FromDomain (the
// From's domain). Level is trusted or untrusted — unknown is the absence of a
// rule, not a rule outcome.
type TrustRule struct {
	From       string `yaml:"from"`
	FromDomain string `yaml:"from_domain"`
	Level      string `yaml:"level"`
	Note       string `yaml:"note"`
}

// Trust levels an operator may set. Anything else is a config error; an omitted
// level maps to the unknown default at stamp time.
const (
	TrustLevelTrusted   = "trusted"
	TrustLevelUntrusted = "untrusted"
)

// maxNoteLen bounds a trust note so it stays a single sane header value.
const maxNoteLen = 512

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
		// Fail-fast on a malformed reconcile interval for an enabled inbox, so a bad
		// duration is caught at load, not at the first reconcile pass (ADR 0026).
		if in.ReconcileEnabled {
			if _, err := in.ReconcileDuration(); err != nil {
				return fmt.Errorf("inboxcfg: inbox %q: %w", name, err)
			}
			if f := in.ReconcileCapFraction; f != 0 && (f < 0 || f > 1) {
				return fmt.Errorf("inboxcfg: inbox %q: reconcile_cap_fraction must be in (0,1], got %v", name, f)
			}
			if fl := in.ReconcileCapFloor; fl != 0 && fl < 1 {
				return fmt.Errorf("inboxcfg: inbox %q: reconcile_cap_floor must be >= 1, got %d", name, fl)
			}
		}
		// Fail-fast on a malformed on-demand-sync debounce window for an enabled
		// inbox, so a bad duration is caught at load, not at the first STATUS
		// (ADR 0028).
		if in.SyncOnStatus {
			if _, err := in.SyncOnStatusDuration(); err != nil {
				return fmt.Errorf("inboxcfg: inbox %q: %w", name, err)
			}
		}
		// Fail-fast on an unknown trust level or a malformed note (ADR 0030), so a
		// bad value is caught at load, not silently mis-stamped at ingest.
		if err := in.validateTrust(); err != nil {
			return fmt.Errorf("inboxcfg: inbox %q: %w", name, err)
		}
	}
	return nil
}

// TrustHeaderValue maps the inbox's configured trust level to the value stamped
// into X-Darbaan-Trust (ADR 0030): trusted/untrusted as configured, else the
// unknown fail-safe default. It reads only config, never message content.
func (in Inbox) TrustHeaderValue() string {
	switch in.Trust.Level {
	case TrustLevelTrusted:
		return provenance.TrustTrusted
	case TrustLevelUntrusted:
		return provenance.TrustUntrusted
	default:
		return provenance.TrustUnknown
	}
}

// validateTrust rejects an unknown trust level and a note that isn't a single
// sane header value (ADR 0030). An omitted level (empty) is valid — it maps to
// the unknown default at stamp time. Note is validated now though it isn't
// stamped until slice 3, so the schema is pinned.
func (in Inbox) validateTrust() error {
	switch in.Trust.Level {
	case "", TrustLevelTrusted, TrustLevelUntrusted:
	default:
		return fmt.Errorf("trust.level %q is invalid (want %q or %q, or omit for unknown)",
			in.Trust.Level, TrustLevelTrusted, TrustLevelUntrusted)
	}
	if err := validateNote(in.Trust.Note); err != nil {
		return fmt.Errorf("trust.note: %w", err)
	}
	return validateRules(in.Trust.Rules)
}

// validateNote rejects a note that isn't a single sane header value (ADR 0030).
func validateNote(note string) error {
	if note == "" {
		return nil
	}
	if len(note) > maxNoteLen {
		return fmt.Errorf("too long (%d > %d bytes)", len(note), maxNoteLen)
	}
	for _, r := range note {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character")
		}
	}
	return nil
}

// validateRules checks each per-sender rule (ADR 0031): exactly one matcher, a
// trusted/untrusted level, a sane note, and no duplicate matcher (which would be
// an ambiguous double-classification of the same sender).
func validateRules(rules []TrustRule) error {
	seenFrom := make(map[string]bool, len(rules))
	seenDomain := make(map[string]bool, len(rules))
	for i, r := range rules {
		hasFrom := strings.TrimSpace(r.From) != ""
		hasDomain := strings.TrimSpace(r.FromDomain) != ""
		if hasFrom == hasDomain {
			return fmt.Errorf("trust.rules[%d]: exactly one of `from` or `from_domain` is required", i)
		}
		if r.Level != TrustLevelTrusted && r.Level != TrustLevelUntrusted {
			return fmt.Errorf("trust.rules[%d]: level %q must be %q or %q", i, r.Level, TrustLevelTrusted, TrustLevelUntrusted)
		}
		if err := validateNote(r.Note); err != nil {
			return fmt.Errorf("trust.rules[%d].note: %w", i, err)
		}
		if hasFrom {
			if k := normAddr(r.From); seenFrom[k] {
				return fmt.Errorf("trust.rules: duplicate from %q", r.From)
			} else {
				seenFrom[k] = true
			}
		} else {
			if k := normDomain(r.FromDomain); seenDomain[k] {
				return fmt.Errorf("trust.rules: duplicate from_domain %q", r.FromDomain)
			} else {
				seenDomain[k] = true
			}
		}
	}
	return nil
}

// SenderStamp resolves the provenance to stamp for a message whose (normalized,
// lower-cased) sender address is `from`, in this inbox (ADR 0031): the
// most-specific matching rule — an exact-address rule beats a domain rule —
// supplies the trust level + note, else the inbox's own default level + note. The
// banner toggle is always the inbox's. `from` == "" (no parseable From) matches
// no rule and takes the inbox default.
func (in Inbox) SenderStamp(from string) provenance.Stamp {
	trust := in.TrustHeaderValue()
	note := in.Trust.Note
	if from != "" {
		if r, ok := in.matchRule(from); ok {
			if r.Level == TrustLevelUntrusted {
				trust = provenance.TrustUntrusted
			} else {
				trust = provenance.TrustTrusted
			}
			note = r.Note
		}
	}
	return provenance.Stamp{Trust: trust, Note: note, Banner: in.Trust.BodyBanner}
}

// matchRule returns the most-specific rule matching from: an exact-address rule
// wins over a domain rule (rules are deduped at load, so at most one per tier).
func (in Inbox) matchRule(from string) (TrustRule, bool) {
	dom := domainOf(from)
	var domainMatch *TrustRule
	for i := range in.Trust.Rules {
		r := in.Trust.Rules[i]
		if r.From != "" && normAddr(r.From) == from {
			return r, true
		}
		if r.FromDomain != "" && dom != "" && normDomain(r.FromDomain) == dom {
			domainMatch = &in.Trust.Rules[i]
		}
	}
	if domainMatch != nil {
		return *domainMatch, true
	}
	return TrustRule{}, false
}

func normAddr(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func normDomain(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[i+1:]
	}
	return ""
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

// ReconcileDuration parses the inbox's reconcile interval (ADR 0026). An empty
// interval returns (0, nil) — the caller substitutes the runtime default. A set
// interval must be a positive Go duration (e.g. "1h", "30m", "6h"); zero or
// negative is an error. It is only meaningful when ReconcileEnabled is set.
func (in Inbox) ReconcileDuration() (time.Duration, error) {
	s := strings.TrimSpace(in.ReconcileInterval)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid reconcile_interval %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("reconcile_interval must be positive, got %q", s)
	}
	return d, nil
}

// SyncOnStatusDuration parses the inbox's on-demand-sync debounce window
// (ADR 0028). An empty interval returns (0, nil) — the caller substitutes the
// runtime default. A set interval must be a positive Go duration (e.g. "15s",
// "1m"); zero or negative is an error. It is only meaningful when SyncOnStatus is
// set.
func (in Inbox) SyncOnStatusDuration() (time.Duration, error) {
	s := strings.TrimSpace(in.SyncOnStatusInterval)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid sync_on_status_interval %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("sync_on_status_interval must be positive, got %q", s)
	}
	return d, nil
}
