package assessor

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/yaad-index/darbaan/internal/riskscore"
)

// Pattern modes for a configured factor (ADR 0035).
const (
	// ModeAugment adds the operator's patterns to the built-in set: the expected
	// case for covering another language.
	ModeAugment = "augment"
	// ModeReplace swaps the built-in set for the operator's patterns. It is the one
	// setting that deletes the defaults, so it must carry examples (see Validate).
	ModeReplace = "replace"
)

// DetectorConfig is the operator's `assessment.detector:` section (ADR 0035). The
// zero value is the built-in detector, unchanged.
type DetectorConfig struct {
	// Disabled switches detection off entirely (`enabled: false` on the section).
	Disabled bool
	// Factors holds per-factor settings, keyed by the scorer's factor names.
	Factors map[riskscore.Factor]FactorConfig
}

// FactorConfig is one factor's entry under `detector:`.
type FactorConfig struct {
	// Enabled nil means "not set", which is enabled.
	Enabled  *bool    `yaml:"enabled"`
	Mode     string   `yaml:"mode"`
	Patterns []string `yaml:"patterns"`
	// Examples are strings the factor's patterns must match at startup. Required
	// for replace; optional for augment, where they must match the ADDED patterns.
	Examples []string `yaml:"examples"`
}

func (f FactorConfig) enabled() bool { return f.Enabled == nil || *f.Enabled }

// ParseDetectorConfig reads the `detector:` key of the assessment section. An
// absent key yields the zero config (built-in behaviour). Decoding is strict: an
// unknown key inside a factor ("pattern:" for "patterns:") fails here, because a
// misspelled key would otherwise load and match nothing, reporting clean results
// the whole time.
func ParseDetectorConfig(section []byte) (DetectorConfig, error) {
	var wrap struct {
		Detector yaml.Node `yaml:"detector"`
	}
	if err := yaml.Unmarshal(section, &wrap); err != nil {
		return DetectorConfig{}, fmt.Errorf("assessor: parse detector config: %w", err)
	}
	var cfg DetectorConfig
	if wrap.Detector.IsZero() {
		return cfg, nil
	}
	if wrap.Detector.Kind != yaml.MappingNode {
		return cfg, errors.New("assessor: detector: must be a mapping")
	}
	nodes := wrap.Detector.Content
	for i := 0; i+1 < len(nodes); i += 2 {
		key, val := nodes[i].Value, nodes[i+1]
		if key == "enabled" {
			var on bool
			if err := val.Decode(&on); err != nil {
				return cfg, fmt.Errorf("assessor: detector.enabled: %w", err)
			}
			cfg.Disabled = !on
			continue
		}
		fc, err := decodeStrict(val)
		if err != nil {
			return cfg, fmt.Errorf("assessor: detector.%s: %w", key, err)
		}
		if cfg.Factors == nil {
			cfg.Factors = make(map[riskscore.Factor]FactorConfig)
		}
		cfg.Factors[riskscore.Factor(key)] = fc
	}
	return cfg, nil
}

// decodeStrict decodes one factor entry, rejecting unknown keys. yaml.Node.Decode
// has no strict mode, so the node is re-encoded and read by a strict decoder.
func decodeStrict(n *yaml.Node) (FactorConfig, error) {
	var fc FactorConfig
	raw, err := yaml.Marshal(n)
	if err != nil {
		return fc, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return fc, err
	}
	return fc, nil
}

// builtinRules is the default ruleset, in rule order. Every factor a rule emits is
// configurable; a factor with no rule (hidden_directives) is not, beyond disabling.
func builtinRules() []rule {
	return []rule{
		{factor: riskscore.FactorInstruction, scope: scopeBody, patterns: instructionPatterns},
		{factor: riskscore.FactorSecretsRequest, scope: scopeAll, patterns: secretsPatterns},
		{factor: riskscore.FactorAttachmentDirectives, scope: scopeAttachments, patterns: instructionPatterns},
	}
}

// NewConfiguredDetector builds the heuristic detector from the operator's config,
// or fails. Validation is total and runs before anything is built, so a bad entry
// fails startup even when the detector or the factor is disabled:
//
//   - an unknown factor name fails, since its patterns would never run;
//   - hidden_directives accepts only `enabled: false`: it has no rule yet, so any
//     patterns there would load and never run;
//   - every pattern must compile;
//   - patterns on a disabled factor fail, since they would never run;
//   - replace needs at least one pattern and at least one example, and every
//     example must match the resulting set, because a replace list that is valid
//     and simply wrong would otherwise match nothing and report clean;
//   - augment examples, if given, must match the ADDED patterns, so a useless
//     addition cannot hide behind the defaults matching.
func NewConfiguredDetector(cfg DetectorConfig) (*HeuristicDetector, error) {
	base := builtinRules()
	byFactor := make(map[riskscore.Factor]int, len(base))
	for i, r := range base {
		byFactor[r.factor] = i
	}
	disabled := make(map[riskscore.Factor]bool)
	for f, fc := range cfg.Factors {
		i, hasRule := byFactor[f]
		if !hasRule {
			if f != riskscore.FactorHiddenDirectives {
				return nil, fmt.Errorf("assessor: detector: unknown factor %q (use a factor_points name that has a detector rule)", f)
			}
			if fc.enabled() || fc.Mode != "" || len(fc.Patterns) > 0 || len(fc.Examples) > 0 {
				return nil, fmt.Errorf("assessor: detector.%s: this factor has no detector rule yet, so only `enabled: false` is accepted", f)
			}
			continue
		}
		added, err := compileOperator(f, fc.Patterns)
		if err != nil {
			return nil, err
		}
		if !fc.enabled() {
			if len(added) > 0 || fc.Mode != "" || len(fc.Examples) > 0 {
				return nil, fmt.Errorf("assessor: detector.%s: patterns, mode or examples on a disabled factor would never run", f)
			}
			disabled[f] = true
			continue
		}
		switch fc.Mode {
		case "", ModeAugment:
			if len(fc.Examples) > 0 {
				if err := checkExamples(f, fc.Examples, added); err != nil {
					return nil, err
				}
			}
			base[i].patterns = append(append([]*regexp.Regexp{}, base[i].patterns...), added...)
		case ModeReplace:
			if len(added) == 0 {
				return nil, fmt.Errorf("assessor: detector.%s: replace needs at least one pattern (to switch the factor off, use `enabled: false`)", f)
			}
			if len(fc.Examples) == 0 {
				return nil, fmt.Errorf("assessor: detector.%s: replace removes the built-in patterns, so it needs at least one example the new patterns must match", f)
			}
			if err := checkExamples(f, fc.Examples, added); err != nil {
				return nil, err
			}
			base[i].patterns = added
		default:
			return nil, fmt.Errorf("assessor: detector.%s: mode %q must be %q or %q", f, fc.Mode, ModeAugment, ModeReplace)
		}
	}
	if cfg.Disabled {
		return &HeuristicDetector{}, nil
	}
	rules := base[:0]
	for _, r := range base {
		if !disabled[r.factor] {
			rules = append(rules, r)
		}
	}
	return &HeuristicDetector{rules: rules}, nil
}

func compileOperator(f riskscore.Factor, exprs []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for i, e := range exprs {
		re, err := regexp.Compile(e)
		if err != nil {
			return nil, fmt.Errorf("assessor: detector.%s.patterns[%d]: %w", f, i, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// checkExamples requires every example to match patterns, after the same
// invisible-rune strip detection applies, so an example is judged exactly as mail
// would be.
func checkExamples(f riskscore.Factor, examples []string, patterns []*regexp.Regexp) error {
	for i, ex := range examples {
		if !matchesAny(stripFormatRunes(ex), patterns) {
			return fmt.Errorf("assessor: detector.%s.examples[%d] %q matches none of the configured patterns", f, i, ex)
		}
	}
	return nil
}
