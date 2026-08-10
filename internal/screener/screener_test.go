package screener

import (
	"context"
	"errors"
	"testing"

	"github.com/yaad-index/darbaan/internal/assessor"
	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/provenance"
	"github.com/yaad-index/darbaan/internal/riskscore"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var declaredAll = []riskscore.Factor{
	riskscore.FactorInstruction,
	riskscore.FactorSecretsRequest,
	riskscore.FactorAttachmentDirectives,
}

// spyDetector records whether Detect ran and returns a configured result.
type spyDetector struct {
	ret   []riskscore.Factor
	err   error
	calls int
}

func (d *spyDetector) Detect(_ context.Context, _ mailtext.Content) ([]riskscore.Factor, error) {
	d.calls++
	return d.ret, d.err
}
func (d *spyDetector) Factors() []riskscore.Factor { return declaredAll }

func mustScorer(t *testing.T, mutate func(*riskscore.Config)) *riskscore.Scorer {
	t.Helper()
	cfg := riskscore.DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := riskscore.New(cfg)
	require.NoError(t, err)
	return s
}

func mustScreener(t *testing.T, sc *riskscore.Scorer, det assessor.Detector, opts ...Option) *Screener {
	t.Helper()
	asr, err := assessor.New(det)
	require.NoError(t, err)
	s, err := New(sc, asr, opts...)
	require.NoError(t, err)
	return s
}

func okContent(_ []byte, _ mailtext.Limits) (mailtext.Content, error) {
	return mailtext.Content{Body: "some body"}, nil
}

func TestNewRequiresComponents(t *testing.T) {
	asr, err := assessor.New(&spyDetector{})
	require.NoError(t, err)
	sc := mustScorer(t, nil)

	_, err = New(nil, asr)
	assert.Error(t, err)
	_, err = New(sc, nil)
	assert.Error(t, err)
}

// TestScreenShortCircuitSkipsAssessor proves cheap-first: when the cheap terms
// gate, neither the extractor nor the assessor runs.
func TestScreenShortCircuitSkipsAssessor(t *testing.T) {
	sc := mustScorer(t, func(c *riskscore.Config) {
		c.SenderBaselines[provenance.TrustUntrusted] = 75 // ≥ threshold 70
	})
	det := &spyDetector{ret: []riskscore.Factor{riskscore.FactorInstruction}}
	extractCalls := 0
	s := mustScreener(t, sc, det, WithExtractor(func(raw []byte, lim mailtext.Limits) (mailtext.Content, error) {
		extractCalls++
		return okContent(raw, lim)
	}))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustUntrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.True(t, out.Result.ShortCircuited)
	assert.Equal(t, 0, det.calls, "the assessor must not run on a short-circuit")
	assert.Equal(t, 0, extractCalls, "extraction must not run on a short-circuit")
	assert.Empty(t, out.Summary)
}

func TestScreenAgentHandled(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{ret: nil} // assessed clean
	s := mustScreener(t, sc, det, WithExtractor(okContent))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionAgentHandled, out.Result.Disposition)
	assert.Equal(t, riskscore.BandLow, out.Result.Band)
	assert.Equal(t, 1, det.calls, "the assessor runs when the cheap terms do not gate")
	assert.NotEmpty(t, out.Summary)
}

func TestScreenMaliciousHeld(t *testing.T) {
	sc := mustScorer(t, nil) // unknown baseline 30 + instruction 40 = 70 → held
	det := &spyDetector{ret: []riskscore.Factor{riskscore.FactorInstruction}}
	s := mustScreener(t, sc, det, WithExtractor(okContent))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustUnknown, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.Equal(t, 70, out.Result.Score)
	assert.Contains(t, out.Result.Factors, riskscore.FactorInstruction)
	assert.Contains(t, out.Summary, string(riskscore.FactorInstruction))
}

func TestScreenExtractionErrorIsNotCleared(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{}
	s := mustScreener(t, sc, det, WithExtractor(func([]byte, mailtext.Limits) (mailtext.Content, error) {
		return mailtext.Content{}, errors.New("boom")
	}))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.True(t, out.Result.NotCleared)
	assert.Equal(t, 0, det.calls, "a failed extraction never reaches the assessor")
	assert.Empty(t, out.Summary)
}

// C20 / Amendment-1: content that extracts to a usable struct but is flagged
// Undecodable (a part could not be decoded, or the structure broke mid-stream)
// must be held fail-safe and must never reach the assessor — the assessor cannot
// vouch for text it never saw, even on an otherwise-trusted sender.
func TestScreenUndecodableIsNotCleared(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{}
	s := mustScreener(t, sc, det, WithExtractor(func([]byte, mailtext.Limits) (mailtext.Content, error) {
		return mailtext.Content{Body: "readable part", Undecodable: true}, nil
	}))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.True(t, out.Result.NotCleared)
	assert.Equal(t, 0, det.calls, "an undecodable extraction never reaches the assessor")
	assert.Empty(t, out.Summary)
}

// A benign cap (Truncated) is NOT a hard-fail: the assessor saw real, bounded
// content, so screening proceeds normally rather than holding.
func TestScreenTruncatedButDecodableProceeds(t *testing.T) {
	sc := mustScorer(t, nil) // trusted baseline is low, no factors → agent-handled
	det := &spyDetector{}
	s := mustScreener(t, sc, det, WithExtractor(func([]byte, mailtext.Limits) (mailtext.Content, error) {
		return mailtext.Content{Body: "bounded body", Truncated: true}, nil
	}))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, 1, det.calls, "a benign cap truncation still runs the assessor")
	assert.False(t, out.Result.NotCleared, "a cap hit is not a fail-safe hold")
}

func TestScreenAssessorErrorIsNotCleared(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{err: errors.New("detector down")}
	s := mustScreener(t, sc, det, WithExtractor(okContent))

	out := s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.True(t, out.Result.NotCleared)
}

// TestScreenRealExtractorEmptyRaw exercises the default (real) extractor: an
// unparseable/empty message fails extraction and is held, not passed.
func TestScreenRealExtractorEmptyRaw(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{}
	s := mustScreener(t, sc, det) // default mailtext.Extract

	out := s.Screen(context.Background(), nil, provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, riskscore.DispositionHeld, out.Result.Disposition)
	assert.True(t, out.Result.NotCleared)
	assert.Equal(t, 0, det.calls)
}

func TestWithLimitsPlumbedToExtractor(t *testing.T) {
	sc := mustScorer(t, nil)
	det := &spyDetector{}
	lim := mailtext.Limits{MaxPartText: 123, MaxTotalText: 456, MaxParts: 7, MaxDepth: 3}
	var got mailtext.Limits
	s := mustScreener(t, sc, det, WithLimits(lim), WithExtractor(func(_ []byte, l mailtext.Limits) (mailtext.Content, error) {
		got = l
		return mailtext.Content{}, nil
	}))
	s.Screen(context.Background(), []byte("raw"), provenance.TrustTrusted, riskscore.RecipientTo)
	assert.Equal(t, lim, got)
}

func TestResolveRecipient(t *testing.T) {
	to := []string{"Me@example.com", "other@example.com"}
	cc := []string{"cc@example.com"}

	assert.Equal(t, riskscore.RecipientTo, ResolveRecipient("me@example.com", to, cc), "case-insensitive To match")
	assert.Equal(t, riskscore.RecipientCc, ResolveRecipient("cc@example.com", to, cc))
	assert.Equal(t, riskscore.RecipientBcc, ResolveRecipient("hidden@example.com", to, cc), "known self not in To/Cc → cautious Bcc")
	// C36: an empty self (identity-less deployment) is a config gap, not hidden
	// delivery — it earns no adjustment (RecipientUnknown), not the Bcc penalty.
	assert.Equal(t, riskscore.RecipientUnknown, ResolveRecipient("", to, cc), "empty self → no adjustment, not Bcc")
	assert.Equal(t, riskscore.RecipientTo, ResolveRecipient(" me@example.com ", to, cc), "trimmed")
}

// C36: RecipientUnknown carries no configured adjustment (an unlisted position
// adds nothing), so an identity-less deployment is not taxed the Bcc penalty on
// every message.
func TestResolveRecipientUnknownHasNoAdjustment(t *testing.T) {
	s, err := riskscore.New(riskscore.DefaultConfig())
	require.NoError(t, err)
	unknown := s.CheapScore(provenance.TrustTrusted, riskscore.RecipientUnknown)
	bcc := s.CheapScore(provenance.TrustTrusted, riskscore.RecipientBcc)
	assert.Equal(t, 0, unknown.Recipient, "unknown position adds nothing")
	assert.Equal(t, 10, bcc.Recipient, "Bcc still carries its +10")
}
