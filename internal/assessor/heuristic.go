package assessor

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// HeuristicDetector is the v1 factor detector: a deterministic pattern ruleset
// (ADR 0032 §5) over the extracted text. It makes no network calls and holds no
// capability — pure text in, factor flags out — so it fits the zero-access seam.
//
// It is BEST-EFFORT / DEFENSE-IN-DEPTH, not the gate. Pattern matching will miss
// novel phrasing (false negatives are expected); the human send-gate and the
// sender-baseline term of the score remain the real backstops. A model-backed
// detector is a fast-follow that drops in behind the same Detector contract,
// behind the isolation this slice proves out.
//
// Not emitted in v1: hidden_directives. Distinguishing hidden text from visible
// requires hidden-segment tagging in the extraction step (a tracked follow-up).
// Until then a directive hidden in, e.g., a display:none span is still caught —
// slice 2 keeps hidden text in the body, so it flags as instruction_to_reader —
// just without the extra hidden-specific weight.
type HeuristicDetector struct {
	rules []rule
}

type matchScope int

const (
	scopeBody matchScope = iota
	scopeAttachments
	scopeAll
)

type rule struct {
	factor   riskscore.Factor
	scope    matchScope
	patterns []*regexp.Regexp
}

// instructionPatterns match directives aimed at the reader — the core of both a
// body instruction and an attachment-smuggled directive.
var instructionPatterns = compileAll(
	`(?i)\bignore\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|preceding|earlier)\s+(instructions?|prompts?|messages?|context|directions?)\b`,
	`(?i)\bdisregard\s+(all\s+|the\s+|any\s+|your\s+)?(previous|prior|above|preceding|earlier)\b`,
	`(?i)\byou\s+are\s+now\b`,
	`(?i)\bnew\s+instructions?\b`,
	`(?i)\bsystem\s+prompt\b`,
	`(?i)\bas\s+an?\s+(ai|assistant|language\s+model)\b`,
	`(?i)\bforward\s+this\s+(email|message|mail)\s+to\b`,
	`(?i)\b(do\s+not|don'?t)\s+(tell|inform|notify|alert|mention)\b`,
	`(?i)\boverride\s+(your|the|all)\s+(instructions?|rules?|settings?)\b`,
)

// secretsPatterns match a REQUEST for credentials or secrets: a request verb
// within a short span of a secret noun (C39). Matching the noun alone fired on
// mere mention — a receipt, a reset notice, a newsletter saying "password" — and,
// with the unknown-sender baseline, held routine mail and trained the operator to
// rubber-stamp. Requiring the verb keeps the true "send me your password" vector
// while dropping bare-noun false positives. The bounded, no-newline gap keeps the
// verb and noun in the same clause without matching across unrelated sentences.
var secretsPatterns = compileAll(
	`(?i)\b(send|share|provide|reveal|give|confirm|enter|submit|verify|forward|paste|type|tell|email|text)\b[^.\r\n]{0,40}?\b(password|passphrase|api[\s-]?keys?|secret\s+keys?|private\s+keys?|ssh\s+keys?|seed\s+phrase|recovery\s+phrase|credentials?|otp|2fa|mfa|one[\s-]?time\s+(?:code|password)|verification\s+code|security\s+code)\b`,
)

// NewHeuristicDetector returns the v1 detector with the default ruleset.
func NewHeuristicDetector() *HeuristicDetector {
	return &HeuristicDetector{rules: builtinRules()}
}

// Detect applies each rule to its scope of the extracted content and returns the
// factors whose patterns match. It never errors on content (best-effort), only on
// a cancelled context.
func (d *HeuristicDetector) Detect(ctx context.Context, c mailtext.Content) ([]riskscore.Factor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []riskscore.Factor
	for _, r := range d.rules {
		// Strip Unicode format runes before matching (C38): zero-width spaces, the
		// bidi controls, word/zero-width joiners, and the soft hyphen are all glyphless
		// and can be interleaved into a keyword ("igno<LRM>re") to defeat the
		// \b-anchored patterns. mailtext keeps them in the served text on purpose
		// (hiding text is itself a signal), so this stripping is match-only and never
		// mutates the content the agent or operator sees.
		if matchesAny(stripFormatRunes(textForScope(c, r.scope)), r.patterns) {
			out = append(out, r.factor)
		}
	}
	return out, nil
}

// stripFormatRunes removes every invisible rune (see isIgnorable) from s, for
// match-only use in detector matching. The fence folds the same class itself, rune
// by rune, so it can map a match back to the original span; both call isIgnorable,
// so the two cannot drift apart. The name predates the class widening beyond Cf
// and is kept because design records cite it. It is safe here precisely because it
// never touches served/stored text; the marginal cost is a rare false merge on a
// visible Arabic prepended-sign rune (which is Cf), erring toward a hold \u2014 the
// right direction for a security matcher.
func stripFormatRunes(s string) string {
	if !strings.ContainsFunc(s, isIgnorable) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isIgnorable(r) {
			return -1
		}
		return r
	}, s)
}

// isIgnorable reports whether r renders as nothing and can therefore be planted
// inside a keyword or a fence marker without changing what a reader sees. It is
// the Unicode default-ignorable class, taken by category and property rather than
// any fixed list, so present and future members are covered:
//   - Cf, the format runes: zero-width space and joiners, BOM, word joiner, the
//     LRM/RLM/ALM bidi marks, the embedding/override/isolate controls, the
//     invisible math operators, the soft hyphen;
//   - Variation_Selector: VS1-16, VS17-256 and the Mongolian free variation
//     selectors, which are category Mn and so escaped a Cf-only test (#251);
//   - Other_Default_Ignorable_Code_Point: the combining grapheme joiner (Mn) and the
//     Hangul fillers, which are even category Lo yet render blank.
func isIgnorable(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// Factors returns the distinct factors this detector can emit (sorted), so
// ValidateAlignment can confirm each has a point-table entry.
func (d *HeuristicDetector) Factors() []riskscore.Factor {
	seen := make(map[riskscore.Factor]struct{}, len(d.rules))
	var out []riskscore.Factor
	for _, r := range d.rules {
		if _, dup := seen[r.factor]; dup {
			continue
		}
		seen[r.factor] = struct{}{}
		out = append(out, r.factor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// textForScope returns the text a rule inspects: the body, the concatenated
// attachment text, or both.
func textForScope(c mailtext.Content, s matchScope) string {
	switch s {
	case scopeBody:
		return c.Body
	case scopeAttachments:
		return attachmentText(c)
	default: // scopeAll
		at := attachmentText(c)
		if at == "" {
			return c.Body
		}
		return c.Body + "\n" + at
	}
}

func attachmentText(c mailtext.Content) string {
	var b strings.Builder
	for _, a := range c.Attachments {
		if a.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(a.Text)
	}
	return b.String()
}

func matchesAny(text string, patterns []*regexp.Regexp) bool {
	if text == "" {
		return false
	}
	for _, p := range patterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

func compileAll(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(exprs))
	for i, e := range exprs {
		out[i] = regexp.MustCompile(e)
	}
	return out
}
