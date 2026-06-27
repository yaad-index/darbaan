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

// YAML shapes. A filter is `default: <action>` plus an ordered `rules:` list;
// each rule is `match:` (AND-ed conditions) + one `action:`.
type fileConfig struct {
	Default string       `yaml:"default"`
	Rules   []ruleConfig `yaml:"rules"`
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

	def := Allow
	if fc.Default != "" {
		a, err := parseAction(fc.Default)
		if err != nil {
			return nil, fmt.Errorf("default: %w", err)
		}
		def = a
	}

	f := &Filter{def: def}
	for i, rc := range fc.Rules {
		action, err := parseAction(rc.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if len(rc.Match) == 0 {
			return nil, fmt.Errorf("rule %d: no match conditions", i+1)
		}
		r := rule{action: action}
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
