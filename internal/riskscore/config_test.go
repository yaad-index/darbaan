package riskscore

import (
	"testing"

	"github.com/yaad-index/darbaan/internal/provenance"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfigValid(t *testing.T) {
	_, err := New(DefaultConfig())
	assert.NoError(t, err)
}

func TestParseEmptyYieldsDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

func TestParsePartialMerge(t *testing.T) {
	cfg, err := Parse([]byte("threshold: 50\n"))
	require.NoError(t, err)
	assert.Equal(t, 50, cfg.Threshold)
	// Untouched fields keep their defaults.
	assert.Equal(t, 33, cfg.Bands.LowMax)
	assert.Equal(t, 0, cfg.SenderBaselines[provenance.TrustTrusted])
	assert.Equal(t, 30, cfg.SenderBaselines[provenance.TrustUnknown])
}

func TestParseMapsMergePerKey(t *testing.T) {
	in := `
sender_baselines:
  untrusted: 80
recipient_adjust:
  cc: 12
factor_points:
  instruction_to_reader: 55
  custom_factor: 15
`
	cfg, err := Parse([]byte(in))
	require.NoError(t, err)

	// Overridden keys take the new value...
	assert.Equal(t, 80, cfg.SenderBaselines[provenance.TrustUntrusted])
	assert.Equal(t, 12, cfg.RecipientAdjust[RecipientCc])
	assert.Equal(t, 55, cfg.FactorPoints[FactorInstruction])
	assert.Equal(t, 15, cfg.FactorPoints[Factor("custom_factor")])
	// ...while sibling keys stay at their defaults (per-key merge, not replace).
	assert.Equal(t, 0, cfg.SenderBaselines[provenance.TrustTrusted])
	assert.Equal(t, 30, cfg.SenderBaselines[provenance.TrustUnknown])
	assert.Equal(t, 0, cfg.RecipientAdjust[RecipientTo])
	assert.Equal(t, 40, cfg.FactorPoints[FactorSecretsRequest])
}

func TestParseBandsMerge(t *testing.T) {
	cfg, err := Parse([]byte("bands:\n  low_max: 20\n"))
	require.NoError(t, err)
	assert.Equal(t, 20, cfg.Bands.LowMax)
	assert.Equal(t, 66, cfg.Bands.MediumMax, "unset medium_max keeps the default")
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("threshold: [not-an-int]\n"))
	assert.Error(t, err)
}

func TestParseValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"low>=medium", "bands:\n  low_max: 66\n  medium_max: 66\n"},
		{"medium>100", "bands:\n  medium_max: 120\n"},
		{"threshold>100", "threshold: 101\n"},
		{"threshold<0", "threshold: -1\n"},
		{"negative factor", "factor_points:\n  instruction_to_reader: -5\n"},
		{"negative baseline", "sender_baselines:\n  untrusted: -1\n"},
		{"unknown recipient", "recipient_adjust:\n  everyone: 5\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			assert.Error(t, err)
		})
	}
}

// TestMissingUnknownBaseline: the fail-safe floor is required. Parse always
// merges onto defaults (which include it), so this is exercised via New directly.
func TestMissingUnknownBaseline(t *testing.T) {
	cfg := DefaultConfig()
	delete(cfg.SenderBaselines, provenance.TrustUnknown)
	_, err := New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}
