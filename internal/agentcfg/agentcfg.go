// Package agentcfg is the multi-agent tenancy config schema (ADR 0027): the
// `agents:` list that sits beside `inboxes:` (ADR 0023). Each agent is a login
// principal with a per-inbox grant list ({read, send}); its password is supplied
// out-of-band via env, never in config (ADR 0012). Sharing an inbox is expressed
// by listing it under more than one agent; privacy is omission — an inbox absent
// from an agent's grants is invisible to it.
//
// A config with no `agents:` list yields a single implicit agent (built by the
// caller) granted read+send on every inbox, so an existing single-agent
// deployment is unchanged (opt-in, exactly like `inboxes:`).
//
// This increment is schema + validation + per-agent authentication. Grant
// ENFORCEMENT — IMAP read-scoping and SMTP send-scoping — lands in the later
// increments; here the schema is parsed, validated, and each agent's default
// inbox resolved, but access is not yet gated.
package agentcfg

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

// Access is one direction an agent may be granted on an inbox (ADR 0027).
const (
	AccessRead = "read"
	AccessSend = "send"
)

// Grant is an agent's access to one inbox: the inbox name and the directions
// granted (a subset of {read, send}). Default marks this grant's inbox as the
// agent's default_inbox — sugar for the top-level DefaultInbox field.
type Grant struct {
	Inbox   string   `yaml:"inbox"`
	Access  []string `yaml:"access"`
	Default bool     `yaml:"default"`
}

// Agent is one login principal (ADR 0027). The password is never a field — it is
// read from the env var named by PasswordEnv(Name), per ADR 0012.
type Agent struct {
	Name         string  `yaml:"name"`
	DefaultInbox string  `yaml:"default_inbox"`
	Grants       []Grant `yaml:"grants"`
}

type fileConfig struct {
	Agents []Agent `yaml:"agents"`
}

// Parse reads the `agents:` list from a config document. An absent or empty
// `agents:` yields nil — the caller substitutes the single implicit agent.
func Parse(data []byte) ([]Agent, error) {
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("agentcfg: parse: %w", err)
	}
	return fc.Agents, nil
}

// PasswordEnv is the env var an agent's Darbaan password is read from (ADR 0012):
// DARBAAN_AGENT_<NAME>_PASSWORD, where <NAME> is mangled by the shared
// inboxcfg.EnvPrefix rule (uppercased, every rune outside [A-Z0-9] → '_'). It is
// the single source of truth for the mangle; Validate's collision guard calls it,
// so a runtime lookup and the load-time check can never diverge. The mangle is
// many-to-one, which is why Validate rejects agent names that collide on it.
func PasswordEnv(name string) string {
	return "DARBAAN_AGENT_" + inboxcfg.EnvPrefix(name) + "_PASSWORD"
}

// HasAccess reports whether the grant includes the given direction.
func (g Grant) HasAccess(dir string) bool {
	for _, a := range g.Access {
		if a == dir {
			return true
		}
	}
	return false
}

// Validate checks an agent list against the configured inbox names: unique agent
// names, unique password-env names (the many-to-one mangle must not silently
// share a secret), and, per agent, a non-empty well-formed grant set whose
// inboxes all exist, plus exactly one resolvable default_inbox with read access
// (ADR 0027). inboxNames is the set of configured inbox names (ADR 0023).
func Validate(agents []Agent, inboxNames map[string]bool) error {
	if len(agents) == 0 {
		return fmt.Errorf("agentcfg: no agents configured")
	}
	seen := make(map[string]bool, len(agents))
	envSeen := make(map[string]string, len(agents)) // password-env → first agent name
	for i, a := range agents {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			return fmt.Errorf("agentcfg: agent %d: name is required", i+1)
		}
		if seen[name] {
			return fmt.Errorf("agentcfg: duplicate agent name %q", name)
		}
		seen[name] = true
		// An agent id and an inbox name share the store's owner namespace once mail
		// is keyed by inbox name (ADR 0027 mail-owner decoupling): an agent named the
		// same as an inbox would collide, so a co-reader could see that agent's
		// private bounces. Reject the overlap.
		if inboxNames[name] {
			return fmt.Errorf("agentcfg: agent name %q collides with an inbox name", name)
		}
		// The password env binding is many-to-one (e.g. "a-b" and "a_b" both mangle
		// to DARBAAN_AGENT_A_B_PASSWORD), so a collision would silently share one
		// secret — reject it at load (ADR 0027).
		env := PasswordEnv(name)
		if other, dup := envSeen[env]; dup {
			return fmt.Errorf("agentcfg: agents %q and %q map to the same password env %q", other, name, env)
		}
		envSeen[env] = name
		if err := validateGrants(name, a.Grants, inboxNames); err != nil {
			return err
		}
		if _, err := DefaultInbox(a); err != nil {
			return err
		}
	}
	return nil
}

// validateGrants checks one agent's grant list: non-empty, each inbox configured
// and granted at most once, each access set non-empty and drawn from {read,send}.
func validateGrants(agent string, grants []Grant, inboxNames map[string]bool) error {
	if len(grants) == 0 {
		return fmt.Errorf("agentcfg: agent %q: at least one grant is required", agent)
	}
	grantSeen := make(map[string]bool, len(grants))
	for _, g := range grants {
		inbox := strings.TrimSpace(g.Inbox)
		if inbox == "" {
			return fmt.Errorf("agentcfg: agent %q: a grant has an empty inbox", agent)
		}
		if !inboxNames[inbox] {
			return fmt.Errorf("agentcfg: agent %q: grant references unknown inbox %q", agent, inbox)
		}
		if grantSeen[inbox] {
			return fmt.Errorf("agentcfg: agent %q: duplicate grant for inbox %q", agent, inbox)
		}
		grantSeen[inbox] = true
		if len(g.Access) == 0 {
			return fmt.Errorf("agentcfg: agent %q: grant for inbox %q has empty access", agent, inbox)
		}
		accessSeen := make(map[string]bool, len(g.Access))
		for _, dir := range g.Access {
			switch dir {
			case AccessRead, AccessSend:
			default:
				return fmt.Errorf("agentcfg: agent %q: grant for inbox %q has unknown access %q (want read/send)", agent, inbox, dir)
			}
			if accessSeen[dir] {
				return fmt.Errorf("agentcfg: agent %q: grant for inbox %q repeats access %q", agent, inbox, dir)
			}
			accessSeen[dir] = true
		}
	}
	return nil
}

// DefaultInbox resolves an agent's default inbox — the mailbox it sees as IMAP
// INBOX and the target of its send catch-all (ADR 0027). Resolution order:
//   - the explicit `default_inbox` field, if set;
//   - else the single grant marked `default: true`;
//   - else, if the agent has exactly one read grant, that inbox (inferred).
//
// The resolved default must be a granted inbox with read access; two or more read
// grants with no explicit default is ambiguous and rejected, as is an explicit
// default that conflicts with a `default: true` grant. Assumes grants are already
// well-formed (see validateGrants).
func DefaultInbox(a Agent) (string, error) {
	name := strings.TrimSpace(a.Name)

	// A `default: true` grant is sugar for the field; if both are given they must
	// agree.
	marked := ""
	for _, g := range a.Grants {
		if g.Default {
			if marked != "" {
				return "", fmt.Errorf("agentcfg: agent %q: more than one grant marked default", name)
			}
			marked = strings.TrimSpace(g.Inbox)
		}
	}
	want := strings.TrimSpace(a.DefaultInbox)
	switch {
	case want != "" && marked != "" && want != marked:
		return "", fmt.Errorf("agentcfg: agent %q: default_inbox %q conflicts with the grant marked default (%q)", name, want, marked)
	case want == "" && marked != "":
		want = marked
	}

	if want == "" {
		// Infer from a lone read grant; ambiguous with two or more.
		var readable []string
		for _, g := range a.Grants {
			if g.HasAccess(AccessRead) {
				readable = append(readable, strings.TrimSpace(g.Inbox))
			}
		}
		switch len(readable) {
		case 1:
			return readable[0], nil
		case 0:
			return "", fmt.Errorf("agentcfg: agent %q: no read grant to serve as default_inbox (INBOX)", name)
		default:
			sort.Strings(readable)
			return "", fmt.Errorf("agentcfg: agent %q: default_inbox is required (has read on %s)", name, strings.Join(readable, ", "))
		}
	}

	// Explicit (or marked) default must be a granted inbox with read access.
	for _, g := range a.Grants {
		if strings.TrimSpace(g.Inbox) != want {
			continue
		}
		if !g.HasAccess(AccessRead) {
			return "", fmt.Errorf("agentcfg: agent %q: default_inbox %q must have read access (it is send-only)", name, want)
		}
		return want, nil
	}
	return "", fmt.Errorf("agentcfg: agent %q: default_inbox %q is not a granted inbox", name, want)
}
