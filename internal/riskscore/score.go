// Package riskscore composes the deterministic injection-risk score for an
// incoming message (ADR 0032). It is the no-model core of the assessment: given
// the trust the gate already stamped (ADR 0030/0031), the recipient position,
// and the set of content factors an isolated assessor flags, it composes a
// 0-100 score by a fixed rule, assigns a labeled band, and decides the
// disposition.
//
// The model never produces the number. An isolated assessor (a later slice)
// only reports which bounded factors it sees; this package turns those flags
// into points via a configured point-table and sums them with the two
// system-supplied terms — the sender baseline and the recipient-position
// adjustment — neither of which touches the model. A compromised assessor can
// therefore lie about which factors it saw, but can never assert a magnitude.
package riskscore

import "fmt"

// MaxScore is the top of the score range. Composed totals are additive and can
// exceed it, so they are clamped into [0, MaxScore] before banding — the score
// stays a real 0-100 number and the bands stay bounded intervals.
const MaxScore = 100

// Factor is a named, bounded content signal an isolated assessor may flag
// (ADR 0032 §3). The assessor reports which factors it sees; the point-table
// (config) turns each into points. Factors below are the v1 vocabulary; the
// table is authoritative, so an operator may add or reweight factors in config.
type Factor string

const (
	// FactorInstruction: the content issues instructions to the reader
	// ("ignore your previous instructions…", "forward this to…").
	FactorInstruction Factor = "instruction_to_reader"
	// FactorSecretsRequest: the content asks for credentials or secrets.
	FactorSecretsRequest Factor = "secrets_request"
	// FactorHiddenDirectives: directives buried in quoted history, zero-width or
	// off-screen text, or HTML-hidden spans.
	FactorHiddenDirectives Factor = "hidden_directives"
	// FactorAttachmentDirectives: directives carried in a decoded attachment.
	FactorAttachmentDirectives Factor = "attachment_directives"
)

// Recipient is the position the assessed mailbox held on the message. Bulk /
// BCC-shaped delivery is a mild risk signal (ADR 0032 §3).
type Recipient string

const (
	RecipientTo  Recipient = "to"
	RecipientCc  Recipient = "cc"
	RecipientBcc Recipient = "bcc"
	// RecipientUnknown is the position for a message whose recipient cannot be
	// resolved because the mailbox's own address is unknown (an identity-less
	// deployment). It carries no configured adjustment — an unlisted position adds
	// nothing (C36) — so a config gap does not tax every message the Bcc penalty.
	// It is distinct from Bcc, which is the cautious position for a KNOWN self that
	// is genuinely absent from To/Cc (real bulk/hidden delivery).
	RecipientUnknown Recipient = ""
)

// Band is the labeled interval a score falls in (ADR 0032 §1). Bands are a
// presentation layer over the number; their cutoffs are config.
type Band string

const (
	BandLow    Band = "low"
	BandMedium Band = "medium"
	BandHigh   Band = "high"
)

// Disposition is what the gate does with the message given its score.
type Disposition string

const (
	// DispositionAgentHandled: the sanitized summary + score + factor list travel
	// with the message into the agent's view (below the human-surface threshold).
	DispositionAgentHandled Disposition = "agent_handled"
	// DispositionHeld: the message is surfaced to a human before the agent sees
	// it (at or above the threshold, or fail-safe).
	DispositionHeld Disposition = "held"
)

// CheapResult is the no-model prefix of the composition: the sender baseline
// plus the recipient-position adjustment (ADR 0032 §5). Both are instant config
// lookups, applied before the expensive content assessor runs.
type CheapResult struct {
	Baseline  int    // sender-baseline component (from the stamped trust level)
	Recipient int    // recipient-position component
	Score     int    // Baseline + Recipient, clamped into [0, MaxScore]
	Trust     string // the trust level used for the baseline (for explainability)
	// Gated is true when the cheap score alone already reaches the human-surface
	// threshold: the caller may skip the content assessor entirely — a known-bad
	// sender is held without the assessor ever running (ADR 0032 §5).
	Gated bool
}

// Result is the composed outcome for one message.
type Result struct {
	Score       int
	Band        Band
	Disposition Disposition
	Baseline    int      // sender-baseline component
	Recipient   int      // recipient-position component
	Factors     []Factor // flagged factors that contributed (nil if short-circuited or none)
	// ShortCircuited is true when the cheap terms reached the threshold and factor
	// tallying was stopped (ADR 0032 §4) — the content assessor was not consulted.
	ShortCircuited bool
	// NotCleared is true for the fail-safe hold: an absent or errored assessment
	// is held regardless of score (ADR 0032 fail-safe).
	NotCleared bool
	Reason     string // human-readable explanation of the disposition
}

// Scorer composes scores against a validated configuration.
type Scorer struct{ cfg Config }

// New returns a Scorer for cfg, or an error if cfg is invalid.
func New(cfg Config) (*Scorer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Scorer{cfg: cfg}, nil
}

// Config returns the scorer's configuration.
func (s *Scorer) Config() Config { return s.cfg }

// baselineFor returns the configured sender baseline for a stamped trust level,
// falling back to the unknown baseline for any unrecognized or empty level
// (fail-safe: an unrecognized trust is treated as unknown, the higher baseline).
func (s *Scorer) baselineFor(trust string) int {
	if v, ok := s.cfg.SenderBaselines[trust]; ok {
		return v
	}
	return s.cfg.SenderBaselines[unknownTrust]
}

// CheapScore returns the no-model prefix — the sender baseline (from the stamped
// trust level) plus the recipient-position adjustment — and whether it already
// reaches the human-surface threshold. It performs no content assessment, so the
// caller can consult it first and skip the expensive assessor when Gated is true
// (cheap-first ordering, ADR 0032 §5).
func (s *Scorer) CheapScore(trust string, r Recipient) CheapResult {
	base := s.baselineFor(trust)
	radj := s.cfg.RecipientAdjust[r] // an unlisted position adds nothing
	score := clamp(base + radj)
	return CheapResult{
		Baseline:  base,
		Recipient: radj,
		Score:     score,
		Trust:     trust,
		Gated:     score >= s.cfg.Threshold,
	}
}

// Compose adds the flagged content factors to a cheap prefix and returns the
// full result. If the cheap prefix already reached the threshold, tallying is
// short-circuited (ADR 0032 §4): the factors are not summed and the message is
// held on the cheap terms alone, still explainable by those terms.
//
// A flagged factor with no point-table entry contributes zero — the table is
// authoritative, and keeping the detector's factor set aligned with the table is
// a configuration concern (the assessor slice validates that alignment).
func (s *Scorer) Compose(cheap CheapResult, factors []Factor) Result {
	if cheap.Gated {
		return Result{
			Score:          cheap.Score,
			Band:           s.band(cheap.Score),
			Disposition:    DispositionHeld,
			Baseline:       cheap.Baseline,
			Recipient:      cheap.Recipient,
			ShortCircuited: true,
			Reason:         "held: sender baseline and recipient position reached the human-surface threshold before content assessment",
		}
	}
	total := cheap.Score
	for _, f := range factors {
		total += s.cfg.FactorPoints[f]
	}
	total = clamp(total)
	disp, reason := s.disposition(total)
	return Result{
		Score:       total,
		Band:        s.band(total),
		Disposition: disp,
		Baseline:    cheap.Baseline,
		Recipient:   cheap.Recipient,
		Factors:     factors,
		Reason:      reason,
	}
}

// Assess is the convenience full path: the cheap prefix followed by the factor
// composition in one call. It is equivalent to Compose(CheapScore(trust, r),
// factors) and is used when the factors are already known (e.g. in tests, or
// once the assessor has run).
func (s *Scorer) Assess(trust string, r Recipient, factors []Factor) Result {
	return s.Compose(s.CheapScore(trust, r), factors)
}

// NotCleared is the fail-safe result for an ambiguous or errored assessment: the
// message is held regardless of any score (ADR 0032 fail-safe). An assessor that
// is absent, unreachable, erroring, or timed out routes here — never
// auto-passed. A reason of "" gets a default explanation.
func NotCleared(reason string) Result {
	if reason == "" {
		reason = "held: assessment not cleared (assessor absent, unreachable, or errored)"
	}
	return Result{
		Disposition: DispositionHeld,
		NotCleared:  true,
		Reason:      reason,
	}
}

// band maps a (clamped) score to its labeled interval.
func (s *Scorer) band(score int) Band {
	switch {
	case score < s.cfg.Bands.LowMax:
		return BandLow
	case score < s.cfg.Bands.MediumMax:
		return BandMedium
	default:
		return BandHigh
	}
}

// disposition maps a (clamped) score to its disposition against the
// human-surface threshold.
func (s *Scorer) disposition(score int) (Disposition, string) {
	if score >= s.cfg.Threshold {
		return DispositionHeld, fmt.Sprintf("held: composed score %d reached the human-surface threshold %d", score, s.cfg.Threshold)
	}
	return DispositionAgentHandled, fmt.Sprintf("agent-handled: composed score %d is below the human-surface threshold %d", score, s.cfg.Threshold)
}

// clamp bounds a raw additive total into [0, MaxScore].
func clamp(n int) int {
	switch {
	case n < 0:
		return 0
	case n > MaxScore:
		return MaxScore
	default:
		return n
	}
}
