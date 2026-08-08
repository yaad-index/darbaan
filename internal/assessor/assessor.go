// Package assessor is the isolated, zero-access injection assessor (ADR 0032
// slice 3). It reads only the extracted text of an untrusted message and reports
// which bounded risk factors it detects — never a score, never an action.
//
// It is the deliberate inverse of the privileged agent: the agent has access but
// must not read raw attacker bytes as trusted; the assessor reads the bytes but
// holds nothing worth hijacking. Structurally it has no mail credentials, no send
// path, no store access, and makes no network calls — an injected payload has
// nothing to seize. This is the load-bearing property of ADR 0032: the gate's
// safety does not depend on the assessor being uncompromised, because even a
// fully-injected assessor can only misreport which factors it saw. It can never
// assert a magnitude (the scorer composes that) or take an action.
//
// The v1 detector is a heuristic pattern ruleset (see HeuristicDetector):
// best-effort and defense-in-depth, NOT the gate. It will miss novel phrasing;
// the human send-gate and the sender-baseline term of the score remain the real
// backstops. A model-backed detector is a fast-follow behind the same Detector
// contract, behind the isolation this package proves out.
package assessor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// Assessment is the assessor's output: the flagged factors and a sanitized
// summary that is safe to surface. It never carries a score — the scorer composes
// that from these factors — and its summary never echoes raw attacker text as
// instructions.
type Assessment struct {
	Factors []riskscore.Factor
	Summary string
}

// Detector detects risk factors in extracted message content. Implementations
// are the tunable part of the assessor (ADR 0032 §5) — a heuristic ruleset now, a
// model-backed client later — behind a fixed contract.
type Detector interface {
	// Detect returns the factors present in c. It MUST return a non-nil error on
	// any failure to assess; an empty slice with a nil error means "assessed,
	// nothing flagged" and may be trusted. This distinction is what makes the
	// fail-safe reliable: a failure is never reported as a clean assessment.
	Detect(ctx context.Context, c mailtext.Content) ([]riskscore.Factor, error)
	// Factors returns every factor this detector can emit, so ValidateAlignment can
	// confirm each has a scorer point-table entry.
	Factors() []riskscore.Factor
}

// Assessor wraps a Detector with the isolation and fail-safe contract. It holds
// no capability beyond the detector and an optional timeout — the zero-access
// seam is that these are its only fields.
type Assessor struct {
	det     Detector
	timeout time.Duration
}

// Option configures an Assessor.
type Option func(*Assessor)

// WithTimeout bounds a single assessment. Zero (the default) adds no bound beyond
// the caller's context.
func WithTimeout(d time.Duration) Option {
	return func(a *Assessor) { a.timeout = d }
}

// New returns an Assessor over det. det must be non-nil: an absent detector is a
// configuration error surfaced here, never a silent pass (fail-safe).
func New(det Detector, opts ...Option) (*Assessor, error) {
	if det == nil {
		return nil, fmt.Errorf("assessor: nil detector")
	}
	a := &Assessor{det: det}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// Assess runs the detector over the extracted content and returns the flagged
// factors plus a sanitized summary. It returns an error on any failure —
// including a cancelled or deadline-exceeded context — so the caller routes it to
// the fail-safe hold (riskscore.NotCleared). It never returns a clean assessment
// on failure.
func (a *Assessor) Assess(ctx context.Context, c mailtext.Content) (Assessment, error) {
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return Assessment{}, fmt.Errorf("assessor: context before assess: %w", err)
	}
	factors, err := a.det.Detect(ctx, c)
	if err != nil {
		return Assessment{}, fmt.Errorf("assessor: detect: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Assessment{}, fmt.Errorf("assessor: context after assess: %w", err)
	}
	factors = dedupeSort(factors)
	return Assessment{Factors: factors, Summary: summarize(factors, c)}, nil
}

// ValidateAlignment checks that every factor the detector can emit has a
// point-table entry in the scorer config, so a detector factor can never silently
// contribute zero (ADR 0032 §3). Call it at wiring time to fail closed on a
// detector/config mismatch.
func ValidateAlignment(det Detector, cfg riskscore.Config) error {
	for _, f := range det.Factors() {
		if _, ok := cfg.FactorPoints[f]; !ok {
			return fmt.Errorf("assessor: detector factor %q has no scorer point-table entry", f)
		}
	}
	return nil
}

// dedupeSort returns the distinct factors in a stable order, so the assessment is
// deterministic regardless of detection order.
func dedupeSort(factors []riskscore.Factor) []riskscore.Factor {
	if len(factors) == 0 {
		return nil
	}
	seen := make(map[riskscore.Factor]struct{}, len(factors))
	out := make([]riskscore.Factor, 0, len(factors))
	for _, f := range factors {
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// summarize renders a sanitized, factual summary. The invariant it must hold: it
// is composed only of system-defined strings that do not vary with message
// content — factor names and a fixed truncation note. It never quotes message
// bytes, so the summary can never relay an injection into whatever consumes it.
func summarize(factors []riskscore.Factor, c mailtext.Content) string {
	var b strings.Builder
	if len(factors) == 0 {
		b.WriteString("No injection-risk factors detected.")
	} else {
		names := make([]string, len(factors))
		for i, f := range factors {
			names[i] = string(f)
		}
		fmt.Fprintf(&b, "Detected injection-risk factors: %s.", strings.Join(names, ", "))
	}
	if c.Truncated {
		b.WriteString(" Note: message content was truncated during extraction.")
	}
	return b.String()
}
