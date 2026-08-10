// Package screener is the injection-assessment orchestrator (ADR 0032 slice 4a):
// the routing-hook logic that ties the deterministic scorer, the isolated
// assessor, and content extraction into a single disposition for one incoming
// message. It is pure — no ingest or serve plumbing — so the security decision
// (pass to the agent vs hold for a human) is reviewable and testable in one place.
//
// The order is cheap-first (ADR 0032 §5): the no-model sender-baseline + recipient
// terms run first, and the expensive content assessor is invoked only when those
// have not already crossed the human-surface threshold. A known-bad sender is
// held without the assessor — or content extraction — ever running.
//
// Fail-safe (ADR 0032): any failure on the assessment path — content that will
// not extract, or an assessor that errors or times out — resolves to a
// not-cleared hold, never an auto-pass.
package screener

import (
	"context"
	"fmt"
	"strings"

	"github.com/yaad-index/darbaan/internal/assessor"
	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// ExtractFunc extracts assessable text from raw message bytes. It matches
// mailtext.Extract and is injectable for testing.
type ExtractFunc func(raw []byte, lim mailtext.Limits) (mailtext.Content, error)

// Outcome is the result of screening one message.
type Outcome struct {
	// Result is the composed score, band, disposition, contributing factors, and
	// (on a fail-safe hold) the NotCleared marker. Callers key routing on
	// Result.Disposition and Result.NotCleared — never on the band/score of a
	// not-cleared hold, which has no composed score.
	Result riskscore.Result
	// Summary is the assessor's sanitized, system-defined summary. It is set only
	// when the content assessor actually ran (not on a short-circuit hold or a
	// fail-safe not-cleared), and never contains message bytes.
	Summary string
}

// Screener orchestrates one message's assessment.
type Screener struct {
	scorer   *riskscore.Scorer
	assessor *assessor.Assessor
	extract  ExtractFunc
	limits   mailtext.Limits
}

// Option configures a Screener.
type Option func(*Screener)

// WithLimits sets the extraction limits (default mailtext.DefaultLimits).
func WithLimits(l mailtext.Limits) Option { return func(s *Screener) { s.limits = l } }

// WithExtractor overrides the content extractor (default mailtext.Extract).
func WithExtractor(fn ExtractFunc) Option { return func(s *Screener) { s.extract = fn } }

// New returns a Screener. Both the scorer and the assessor are required: once
// assessment is running, an absent component is a configuration error, never a
// silent pass. ValidateAlignment(detector, scorer.Config()) is a wiring-time
// check the caller runs at startup (fail closed on a detector/config mismatch).
func New(scorer *riskscore.Scorer, asr *assessor.Assessor, opts ...Option) (*Screener, error) {
	if scorer == nil {
		return nil, fmt.Errorf("screener: nil scorer")
	}
	if asr == nil {
		return nil, fmt.Errorf("screener: nil assessor")
	}
	s := &Screener{scorer: scorer, assessor: asr, extract: mailtext.Extract, limits: mailtext.DefaultLimits()}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Screen assesses one incoming message and returns its disposition. trust is the
// level the gate already stamped (provenance.Trust*, ADR 0030/0031) — never a
// re-read of From — and recipient is the position the assessed mailbox held.
//
// Cheap-first: the sender-baseline + recipient terms are scored first; if they
// alone reach the threshold the message is held immediately, and neither content
// extraction nor the assessor runs. Otherwise the content is extracted and
// assessed, and the factors are composed into the final score. Any failure on
// that path is a fail-safe not-cleared hold.
func (s *Screener) Screen(ctx context.Context, raw []byte, trust string, recipient riskscore.Recipient) Outcome {
	cheap := s.scorer.CheapScore(trust, recipient)
	if cheap.Gated {
		// Short-circuit: held on the cheap terms alone; the assessor never runs.
		return Outcome{Result: s.scorer.Compose(cheap, nil)}
	}
	content, err := s.extract(raw, s.limits)
	if err != nil {
		return Outcome{Result: riskscore.NotCleared(fmt.Sprintf("held: content could not be extracted for assessment: %v", err))}
	}
	if content.Undecodable {
		// Extraction hard-failed on a part (unreadable/undecodable) or the MIME
		// structure broke mid-stream (C19/C20): text the message carries never
		// reached the assessor, so it cannot be cleared — fail-safe hold (ADR 0032
		// Amendment 1). A benign cap (content.Truncated) is not a hard-fail and does
		// not hold: the assessor saw real, bounded content.
		return Outcome{Result: riskscore.NotCleared("held: message content could not be fully decoded for assessment (a part was unreadable or the MIME structure was malformed)")}
	}
	assessment, err := s.assessor.Assess(ctx, content)
	if err != nil {
		return Outcome{Result: riskscore.NotCleared(fmt.Sprintf("held: assessment did not complete: %v", err))}
	}
	return Outcome{
		Result:  s.scorer.Compose(cheap, assessment.Factors),
		Summary: assessment.Summary,
	}
}

// ResolveRecipient returns the position the mailbox self held on a message with
// the given To and Cc recipient addresses. To wins over Cc. A KNOWN self found in
// neither — delivered via Bcc, an alias, or a list — is treated as the most
// cautious position, Bcc, since bulk/hidden delivery is a mild risk signal
// (ADR 0032 §3) and an unresolved position should never earn the safest score.
//
// An EMPTY self (an identity-less deployment: the inbox has no configured send
// identity to match against To/Cc) is a configuration gap, not a delivery signal.
// Its position cannot be resolved, so it earns RecipientUnknown — no adjustment —
// rather than the Bcc penalty, which would otherwise add +10 to every message the
// deployment ever assesses (C36).
func ResolveRecipient(self string, to, cc []string) riskscore.Recipient {
	self = normalizeAddr(self)
	if self == "" {
		return riskscore.RecipientUnknown
	}
	if containsAddr(to, self) {
		return riskscore.RecipientTo
	}
	if containsAddr(cc, self) {
		return riskscore.RecipientCc
	}
	return riskscore.RecipientBcc
}

func containsAddr(list []string, self string) bool {
	for _, a := range list {
		if normalizeAddr(a) == self {
			return true
		}
	}
	return false
}

func normalizeAddr(a string) string {
	return strings.ToLower(strings.TrimSpace(a))
}
