package riskscore

import (
	"testing"

	"github.com/yaad-index/darbaan/internal/provenance"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scorerWith returns a scorer built from the defaults with an override applied.
func scorerWith(t *testing.T, mutate func(*Config)) *Scorer {
	t.Helper()
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	require.NoError(t, err)
	return s
}

func TestBandBoundaries(t *testing.T) {
	// A trusted baseline set to the target, recipient "to" (0), no factors, yields
	// a composed score equal to the target — so we can probe band edges directly.
	cases := []struct {
		score int
		want  Band
	}{
		{0, BandLow}, {1, BandLow}, {32, BandLow},
		{33, BandMedium}, {50, BandMedium}, {65, BandMedium},
		{66, BandHigh}, {99, BandHigh}, {100, BandHigh},
	}
	for _, c := range cases {
		s := scorerWith(t, func(cfg *Config) { cfg.SenderBaselines[provenance.TrustTrusted] = c.score })
		got := s.Assess(provenance.TrustTrusted, RecipientTo, nil)
		assert.Equalf(t, c.want, got.Band, "score %d", c.score)
		assert.Equalf(t, c.score, got.Score, "score %d", c.score)
	}
}

// TestClampExceeds100 covers the review clamp note: the additive formula can
// exceed 100, and the composed score is clamped into the range before banding.
func TestClampExceeds100(t *testing.T) {
	s := scorerWith(t, nil) // defaults: untrusted 40, bcc 10, instruction 40, secrets 40 = 130
	got := s.Assess(provenance.TrustUntrusted, RecipientBcc,
		[]Factor{FactorInstruction, FactorSecretsRequest})
	assert.Equal(t, MaxScore, got.Score, "over-100 total clamps to MaxScore")
	assert.Equal(t, BandHigh, got.Band)
	assert.Equal(t, DispositionHeld, got.Disposition)
	assert.False(t, got.ShortCircuited, "untrusted(40)+bcc(10)=50 is below the 70 threshold, so factors are tallied")
}

func TestDispositionAgainstThreshold(t *testing.T) {
	s := scorerWith(t, nil) // threshold 70

	// trusted(0) + to(0) + instruction(40) = 40 → below threshold → agent-handled.
	below := s.Assess(provenance.TrustTrusted, RecipientTo, []Factor{FactorInstruction})
	assert.Equal(t, 40, below.Score)
	assert.Equal(t, BandMedium, below.Band)
	assert.Equal(t, DispositionAgentHandled, below.Disposition)

	// unknown(30) + to(0) + instruction(40) = 70 → reaches threshold → held.
	at := s.Assess(provenance.TrustUnknown, RecipientTo, []Factor{FactorInstruction})
	assert.Equal(t, 70, at.Score)
	assert.Equal(t, BandHigh, at.Band)
	assert.Equal(t, DispositionHeld, at.Disposition)
}

// TestShortCircuitStopsTally proves the cheap terms gate the summation: once the
// baseline+recipient reach the threshold, the factors are NOT added (the score
// stays at the cheap total) and the assessor's factor set is not recorded.
func TestShortCircuitStopsTally(t *testing.T) {
	s := scorerWith(t, func(cfg *Config) { cfg.SenderBaselines[provenance.TrustUntrusted] = 70 })

	cheap := s.CheapScore(provenance.TrustUntrusted, RecipientTo)
	require.True(t, cheap.Gated, "untrusted baseline 70 alone reaches the threshold")

	got := s.Compose(cheap, []Factor{FactorInstruction, FactorSecretsRequest})
	assert.True(t, got.ShortCircuited)
	assert.Equal(t, 70, got.Score, "tally stops at the cheap total; factor points are not added")
	assert.Equal(t, DispositionHeld, got.Disposition)
	assert.Empty(t, got.Factors, "factors are not recorded on a short-circuit")
}

func TestCheapScoreGating(t *testing.T) {
	// Default: unknown baseline 30 + to 0 = 30 < 70 → not gated.
	s := scorerWith(t, nil)
	c := s.CheapScore(provenance.TrustUnknown, RecipientTo)
	assert.Equal(t, 30, c.Score)
	assert.Equal(t, 30, c.Baseline)
	assert.Equal(t, 0, c.Recipient)
	assert.False(t, c.Gated)

	// Raise the untrusted baseline to the threshold → gated on the cheap terms.
	s2 := scorerWith(t, func(cfg *Config) { cfg.SenderBaselines[provenance.TrustUntrusted] = 75 })
	c2 := s2.CheapScore(provenance.TrustUntrusted, RecipientTo)
	assert.True(t, c2.Gated)
}

// TestUnknownTrustFallback: an unrecognized trust level uses the unknown floor.
func TestUnknownTrustFallback(t *testing.T) {
	s := scorerWith(t, nil)
	c := s.CheapScore("some-unrecognized-level", RecipientTo)
	assert.Equal(t, s.Config().SenderBaselines[provenance.TrustUnknown], c.Baseline)
	assert.Equal(t, "some-unrecognized-level", c.Trust)
}

// TestUnknownFactorContributesZero: the point-table is authoritative.
func TestUnknownFactorContributesZero(t *testing.T) {
	s := scorerWith(t, nil)
	only := s.Assess(provenance.TrustTrusted, RecipientTo, []Factor{Factor("not_in_table")})
	assert.Equal(t, 0, only.Score)

	mixed := s.Assess(provenance.TrustTrusted, RecipientTo, []Factor{FactorInstruction, Factor("not_in_table")})
	assert.Equal(t, 40, mixed.Score, "only the known factor contributes")
}

func TestRecipientAdjust(t *testing.T) {
	s := scorerWith(t, nil)
	assert.Equal(t, 0, s.Assess(provenance.TrustTrusted, RecipientTo, nil).Score)
	assert.Equal(t, 5, s.Assess(provenance.TrustTrusted, RecipientCc, nil).Score)
	assert.Equal(t, 10, s.Assess(provenance.TrustTrusted, RecipientBcc, nil).Score)
	assert.Equal(t, 0, s.Assess(provenance.TrustTrusted, Recipient("unlisted"), nil).Score,
		"an unlisted recipient position adds nothing")
}

func TestNotCleared(t *testing.T) {
	def := NotCleared("")
	assert.Equal(t, DispositionHeld, def.Disposition)
	assert.True(t, def.NotCleared)
	assert.NotEmpty(t, def.Reason)

	custom := NotCleared("held: assessor RPC timed out")
	assert.Equal(t, "held: assessor RPC timed out", custom.Reason)
	assert.True(t, custom.NotCleared)
	assert.Equal(t, DispositionHeld, custom.Disposition)
}

func TestAssessEqualsStagedCompose(t *testing.T) {
	s := scorerWith(t, nil)
	factors := []Factor{FactorHiddenDirectives}
	staged := s.Compose(s.CheapScore(provenance.TrustUnknown, RecipientCc), factors)
	oneShot := s.Assess(provenance.TrustUnknown, RecipientCc, factors)
	assert.Equal(t, staged, oneShot)
}

// TestResultExplainability: a non-gated result carries its components + factors.
func TestResultExplainability(t *testing.T) {
	s := scorerWith(t, nil)
	factors := []Factor{FactorInstruction, FactorHiddenDirectives}
	got := s.Assess(provenance.TrustUnknown, RecipientCc, factors)
	assert.Equal(t, 30, got.Baseline)
	assert.Equal(t, 5, got.Recipient)
	assert.Equal(t, factors, got.Factors)
	assert.False(t, got.ShortCircuited)
	assert.NotEmpty(t, got.Reason)
}

func TestClampNegativeFloor(t *testing.T) {
	assert.Equal(t, 0, clamp(-5))
	assert.Equal(t, 0, clamp(0))
	assert.Equal(t, 42, clamp(42))
	assert.Equal(t, MaxScore, clamp(MaxScore+1))
}
