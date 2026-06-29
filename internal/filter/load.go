package filter

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// YAML shapes. A filter is a per-inbox default disposition plus an ordered
// `rules:` list; each rule is `match:` (AND-ed conditions) + an optional
// `action:`. The disposition is `default_visibility: visible|hidden` (ADR 0022)
// and fixes both the no-match default and what a bare (action-less) rule does.
// The legacy `default: <action>` (ADR 0008/0021) is still honored for back-compat.
type fileConfig struct {
	DefaultVisibility string       `yaml:"default_visibility"`
	Default           string       `yaml:"default"`
	Rules             []ruleConfig `yaml:"rules"`
}

type ruleConfig struct {
	Match  []condConfig `yaml:"match"`
	Action string       `yaml:"action"`
}

type condConfig struct {
	Field  string `yaml:"field"`
	Header string `yaml:"header,omitempty"`
	Op     string `yaml:"op"`
	Value  string `yaml:"value"`
}

// Load reads and compiles a filter from a YAML file. An empty path yields a
// pass-through filter (default allow, no rules) so the filter is off by default.
func Load(path string) (*Filter, error) {
	if path == "" {
		return &Filter{def: Allow}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("filter: read %s: %w", path, err)
	}
	f, err := Compile(data)
	if err != nil {
		return nil, fmt.Errorf("filter: %s: %w", path, err)
	}
	return f, nil
}

// Compile parses + validates YAML into a Filter. Validation is fail-fast: a bad
// rule set is a config error at serve start, never a silently-ignored rule.
func Compile(data []byte) (*Filter, error) {
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	def, flip, flipSet, err := resolveDefault(fc)
	if err != nil {
		return nil, err
	}

	f := &Filter{def: def}
	for i, rc := range fc.Rules {
		// A bare rule (no action:) takes the inverse of the default disposition
		// — a match flips visibility (ADR 0022). An explicit action wins and is
		// parsed as today; hold-for-human is therefore never implied by the mode.
		var (
			action  Action
			implied bool
		)
		if rc.Action == "" {
			if !flipSet {
				return nil, fmt.Errorf("rule %d: no action and no default disposition to imply one (set default_visibility, or give the rule an explicit action)", i+1)
			}
			action, implied = flip, true
		} else {
			action, err = parseAction(rc.Action)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
		if len(rc.Match) == 0 {
			return nil, fmt.Errorf("rule %d: no match conditions", i+1)
		}
		r := rule{action: action, implied: implied}
		for j, cc := range rc.Match {
			c, err := compileCond(cc)
			if err != nil {
				return nil, fmt.Errorf("rule %d condition %d: %w", i+1, j+1, err)
			}
			r.conds = append(r.conds, c)
		}
		f.rules = append(f.rules, r)
	}
	return f, nil
}

// visibility dispositions (ADR 0022).
const (
	visVisible = "visible"
	visHidden  = "hidden"
)

// resolveDefault reconciles the first-class default_visibility/mode disposition
// with the legacy default: action into the no-match action (def) and the action
// a bare rule resolves to (flip; flipSet is false when no disposition implies
// one — legacy default: hold-for-human, which has no visibility inverse).
//
// Precedence: an explicit default_visibility (or mode alias) sets the
// disposition; a legacy default:, if also present, must agree. With only a
// legacy default:, honor it (back-compat). With neither, the implicit default is
// visible (default-allow) — every existing ADR 0021 config keeps working.
func resolveDefault(fc fileConfig) (def, flip Action, flipSet bool, err error) {
	vis, err := normVisibility(fc.DefaultVisibility)
	if err != nil {
		return "", "", false, err
	}

	var legacy Action
	if fc.Default != "" {
		legacy, err = parseAction(fc.Default)
		if err != nil {
			return "", "", false, fmt.Errorf("default: %w", err)
		}
	}

	if vis != "" {
		d := Allow
		if vis == visHidden {
			d = Hide
		}
		if fc.Default != "" && legacy != d {
			return "", "", false, fmt.Errorf("default_visibility: %s conflicts with default: %s (use one)", vis, fc.Default)
		}
		return d, inverse(d), true, nil
	}

	if fc.Default != "" {
		switch legacy {
		case Allow:
			return Allow, Hide, true, nil
		case Hide:
			return Hide, Allow, true, nil
		default: // Hold has no visibility inverse: bare rules are not implied.
			return legacy, "", false, nil
		}
	}

	return Allow, Hide, true, nil
}

// inverse flips a visibility action (allow<->hide). Only called for Allow/Hide.
func inverse(a Action) Action {
	if a == Allow {
		return Hide
	}
	return Allow
}

// normVisibility normalizes default_visibility into "" | visible | hidden.
// (whitelist=visible / blacklist=hidden is conceptual framing in the ADR/docs,
// not config surface — ADR 0022.)
func normVisibility(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case visVisible:
		return visVisible, nil
	case visHidden:
		return visHidden, nil
	}
	return "", fmt.Errorf("default_visibility: unknown %q (visible|hidden)", s)
}

func parseAction(s string) (Action, error) {
	switch Action(s) {
	case Allow, Hide, Hold:
		return Action(s), nil
	}
	return "", fmt.Errorf("unknown action %q (allow|hide|hold-for-human)", s)
}

func compileCond(cc condConfig) (cond, error) {
	c := cond{field: strings.ToLower(cc.Field), op: strings.ToLower(cc.Op)}

	if c.field == fieldAge {
		if c.op != opOlderThan && c.op != opNewerThan {
			return cond{}, fmt.Errorf("age op must be older_than|newer_than, got %q", cc.Op)
		}
		d, err := parseDur(cc.Value)
		if err != nil {
			return cond{}, err
		}
		c.dur = d
		return c, nil
	}

	switch c.field {
	case fieldFrom, fieldTo, fieldCc, fieldSubject, fieldLabel:
	case fieldHeader:
		c.header = strings.ToLower(cc.Header)
		if !envelopeHeaders[c.header] {
			return cond{}, fmt.Errorf("header %q not matchable in v1 (envelope headers only: from/to/cc/subject/date/message-id/reply-to)", cc.Header)
		}
	default:
		return cond{}, fmt.Errorf("unknown field %q", cc.Field)
	}

	switch c.op {
	case opEquals, opContains, opRegex:
	case opDomain:
		if !isAddressCond(c.field, c.header) {
			return cond{}, fmt.Errorf("op domain only applies to address fields")
		}
	default:
		return cond{}, fmt.Errorf("unknown op %q (equals|contains|regex|domain)", cc.Op)
	}

	if cc.Value == "" {
		return cond{}, fmt.Errorf("empty value")
	}
	if c.op == opRegex {
		re, err := regexp.Compile(cc.Value)
		if err != nil {
			return cond{}, fmt.Errorf("regex: %w", err)
		}
		c.re = re
		c.value = cc.Value
	} else {
		c.value = strings.ToLower(cc.Value) // equals/contains/domain are case-insensitive
	}
	return c, nil
}

// isAddressCond reports whether a condition targets an address field (the only
// fields the `domain` operator applies to).
func isAddressCond(field, header string) bool {
	switch field {
	case fieldFrom, fieldTo, fieldCc:
		return true
	case fieldHeader:
		return header == "from" || header == "to" || header == "cc" || header == "reply-to"
	}
	return false
}

// parseDur parses an age duration: time.ParseDuration units plus calendar d/w/y.
func parseDur(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	units := map[byte]time.Duration{
		'd': 24 * time.Hour,
		'w': 7 * 24 * time.Hour,
		'y': 365 * 24 * time.Hour,
	}
	if mult, ok := units[s[len(s)-1]]; ok {
		val, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(val * float64(mult)), nil
	}
	return time.ParseDuration(s)
}
