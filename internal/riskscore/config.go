package riskscore

import (
	"fmt"

	"github.com/yaad-index/darbaan/internal/provenance"

	"gopkg.in/yaml.v3"
)

// unknownTrust is the trust level used as the sender-baseline fail-safe floor:
// an unrecognized or empty trust maps here (ADR 0030's fail-safe default).
const unknownTrust = provenance.TrustUnknown

// Config is the tunable schema for the deterministic scorer (ADR 0032 §7). Every
// weight is operator configuration; only the composition shape is fixed.
type Config struct {
	// SenderBaselines maps a stamped trust level (provenance.Trust*: "trusted",
	// "untrusted", "unknown") to the baseline points a message from such a source
	// starts with. Keyed on the trust the gate already stamped (ADR 0030/0031),
	// never on a re-read of From. Must define the "unknown" floor.
	SenderBaselines map[string]int `yaml:"sender_baselines"`
	// RecipientAdjust maps a recipient position (to/cc/bcc) to its point
	// adjustment; an unlisted position adds nothing.
	RecipientAdjust map[Recipient]int `yaml:"recipient_adjust"`
	// FactorPoints is the point-table: each flagged content factor's contribution.
	// The table is authoritative — a flagged factor with no entry adds nothing.
	FactorPoints map[Factor]int `yaml:"factor_points"`
	// Bands are the labeled-interval cutoffs over the 0-100 score.
	Bands Bands `yaml:"bands"`
	// Threshold is the human-surface cutoff: a composed score at or above it is
	// held for a human. Default is HIGH (see DefaultConfig); lower it for a more
	// conservative posture.
	Threshold int `yaml:"threshold"`
}

// Bands holds the band cutoffs. A score below LowMax is low; below MediumMax is
// medium; at or above MediumMax is high.
type Bands struct {
	LowMax    int `yaml:"low_max"`
	MediumMax int `yaml:"medium_max"`
}

// DefaultConfig returns the v1 default weights: a source-trust gradient on the
// sender baseline, a mild bulk/BCC-shaped adjustment, the four v1 factors, bands
// at 33/66, and a HIGH human-surface threshold (70) — low and medium bands flow
// to the agent, only high is held.
func DefaultConfig() Config {
	return Config{
		SenderBaselines: map[string]int{
			provenance.TrustTrusted:   0,
			provenance.TrustUntrusted: 40,
			provenance.TrustUnknown:   30,
		},
		RecipientAdjust: map[Recipient]int{
			RecipientTo:  0,
			RecipientCc:  5,
			RecipientBcc: 10,
		},
		FactorPoints: map[Factor]int{
			FactorInstruction:          40,
			FactorSecretsRequest:       40,
			FactorHiddenDirectives:     30,
			FactorAttachmentDirectives: 30,
		},
		Bands:     Bands{LowMax: 33, MediumMax: 66},
		Threshold: 70,
	}
}

// yamlConfig is the on-disk shape. Scalars are pointers so an omitted key is
// distinguishable from an explicit zero (a zero threshold is a valid, very
// strict setting); maps are overlaid per key onto the defaults.
type yamlConfig struct {
	SenderBaselines map[string]int    `yaml:"sender_baselines"`
	RecipientAdjust map[Recipient]int `yaml:"recipient_adjust"`
	FactorPoints    map[Factor]int    `yaml:"factor_points"`
	Bands           *struct {
		LowMax    *int `yaml:"low_max"`
		MediumMax *int `yaml:"medium_max"`
	} `yaml:"bands"`
	Threshold *int `yaml:"threshold"`
}

// Parse unmarshals the injection-assessment config from YAML, overlaying any
// provided values onto DefaultConfig (maps merge per key, so a partial config is
// valid), then validates. A nil/empty input yields the validated defaults.
func Parse(data []byte) (Config, error) {
	var yc yamlConfig
	if err := yaml.Unmarshal(data, &yc); err != nil {
		return Config{}, fmt.Errorf("riskscore: parse config: %w", err)
	}
	cfg := DefaultConfig()
	for k, v := range yc.SenderBaselines {
		cfg.SenderBaselines[k] = v
	}
	for k, v := range yc.RecipientAdjust {
		cfg.RecipientAdjust[k] = v
	}
	for k, v := range yc.FactorPoints {
		cfg.FactorPoints[k] = v
	}
	if yc.Bands != nil {
		if yc.Bands.LowMax != nil {
			cfg.Bands.LowMax = *yc.Bands.LowMax
		}
		if yc.Bands.MediumMax != nil {
			cfg.Bands.MediumMax = *yc.Bands.MediumMax
		}
	}
	if yc.Threshold != nil {
		cfg.Threshold = *yc.Threshold
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate enforces the invariants the scorer relies on.
func (c Config) validate() error {
	if c.Bands.LowMax < 0 || c.Bands.MediumMax < 0 {
		return fmt.Errorf("riskscore: band cutoffs must be non-negative (low_max=%d medium_max=%d)", c.Bands.LowMax, c.Bands.MediumMax)
	}
	if c.Bands.LowMax >= c.Bands.MediumMax {
		return fmt.Errorf("riskscore: low_max (%d) must be less than medium_max (%d)", c.Bands.LowMax, c.Bands.MediumMax)
	}
	if c.Bands.MediumMax > MaxScore {
		return fmt.Errorf("riskscore: medium_max (%d) must not exceed %d", c.Bands.MediumMax, MaxScore)
	}
	if c.Threshold < 0 || c.Threshold > MaxScore {
		return fmt.Errorf("riskscore: threshold (%d) must be within [0, %d]", c.Threshold, MaxScore)
	}
	if _, ok := c.SenderBaselines[unknownTrust]; !ok {
		return fmt.Errorf("riskscore: sender_baselines must define %q (the fail-safe floor)", unknownTrust)
	}
	for k, v := range c.SenderBaselines {
		if v < 0 {
			return fmt.Errorf("riskscore: sender_baseline %q must be non-negative (got %d)", k, v)
		}
	}
	for k, v := range c.RecipientAdjust {
		switch k {
		case RecipientTo, RecipientCc, RecipientBcc:
		default:
			return fmt.Errorf("riskscore: unknown recipient position %q (want to/cc/bcc)", k)
		}
		if v < 0 {
			return fmt.Errorf("riskscore: recipient_adjust %q must be non-negative (got %d)", k, v)
		}
	}
	for k, v := range c.FactorPoints {
		if v < 0 {
			return fmt.Errorf("riskscore: factor_points %q must be non-negative (got %d)", k, v)
		}
	}
	return nil
}
