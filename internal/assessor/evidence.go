package assessor

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yaad-index/darbaan/internal/mailtext"
	"github.com/yaad-index/darbaan/internal/riskscore"
)

// Evidence bounds (ADR 0036): a fixed number of spans per factor, each a fixed
// length including a little context on either side of the match.
const (
	MaxSpansPerFactor = 3
	MaxSpanRunes      = 200
	spanContextRunes  = 40
)

// SourceBody labels a span found in the message body; a span found in an
// attachment is labelled with the attachment's filename.
const SourceBody = "body"

// Span is one piece of text a rule matched, with a little context, for the
// operator to judge. It is transient: it is computed when a hold card is built
// and never stored (ADR 0036).
type Span struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

// Evidence re-runs the rule of each requested factor over c and returns the spans
// it matches, keyed by factor. Every requested factor has an entry: an empty
// slice means the current rules no longer match this message for that factor,
// which the caller must show as such rather than as "nothing matched".
//
// It matches exactly the text Detect matches: the rule's scope, with the same
// invisible-rune strip, joined the same way, so a factor that fired is found
// again unless the rules or the content have changed since.
func (d *HeuristicDetector) Evidence(c mailtext.Content, factors []riskscore.Factor) map[riskscore.Factor][]Span {
	out := make(map[riskscore.Factor][]Span, len(factors))
	for _, f := range factors {
		out[f] = []Span{}
	}
	for _, r := range d.rules {
		if _, want := out[r.factor]; !want {
			continue
		}
		text, segs := scopedSegments(c, r.scope)
		out[r.factor] = collectSpans(text, segs, r.patterns)
	}
	return out
}

// segment is one source's slice of a scoped text: [start, end) in bytes.
type segment struct {
	source     string
	start, end int
}

// scopedSegments builds the same text Detect matches for a scope, after the same
// strip, and records which source each byte range came from. Stripping per piece
// and joining equals stripping the join, because the newline separator is never
// an invisible rune.
func scopedSegments(c mailtext.Content, s matchScope) (string, []segment) {
	type piece struct{ source, text string }
	var pieces []piece
	if s == scopeBody || s == scopeAll {
		pieces = append(pieces, piece{SourceBody, c.Body})
	}
	if s == scopeAttachments || s == scopeAll {
		for i, a := range c.Attachments {
			if a.Text == "" {
				continue
			}
			name := a.Filename
			if name == "" {
				name = "attachment " + strconv.Itoa(i+1)
			}
			pieces = append(pieces, piece{name, a.Text})
		}
	}
	// scopeAll with an empty attachment set is the body alone, as in textForScope;
	// an empty body is still joined when attachments follow, also as there.
	var b strings.Builder
	var segs []segment
	for i, p := range pieces {
		if i > 0 {
			b.WriteByte('\n')
		}
		start := b.Len()
		b.WriteString(stripFormatRunes(p.text))
		segs = append(segs, segment{p.source, start, b.Len()})
	}
	return b.String(), segs
}

// collectSpans returns up to MaxSpansPerFactor distinct matches across the
// patterns, in text order, each labelled with the source it starts in.
func collectSpans(text string, segs []segment, patterns []*regexp.Regexp) []Span {
	type hit struct{ start, end int }
	var hits []hit
	seen := map[int]bool{}
	for _, p := range patterns {
		for _, m := range p.FindAllStringIndex(text, -1) {
			if !seen[m[0]] {
				seen[m[0]] = true
				hits = append(hits, hit{m[0], m[1]})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].start < hits[j].start })
	spans := []Span{}
	for _, h := range hits {
		if len(spans) == MaxSpansPerFactor {
			break
		}
		spans = append(spans, Span{Source: sourceAt(segs, h.start), Text: snippet(text, h.start, h.end)})
	}
	return spans
}

func sourceAt(segs []segment, at int) string {
	for _, s := range segs {
		if at >= s.start && at < s.end {
			return s.source
		}
	}
	if len(segs) > 0 {
		return segs[len(segs)-1].source
	}
	return SourceBody
}

// snippet returns the match with up to spanContextRunes of context on each side,
// bounded to MaxSpanRunes. The match itself is never cut for context: context is
// dropped first, and only a match longer than the bound is shortened, with an
// ellipsis marking the cut.
func snippet(text string, start, end int) string {
	match := text[start:end]
	if utf8.RuneCountInString(match) >= MaxSpanRunes {
		return truncateRunes(match, MaxSpanRunes-1) + "…"
	}
	room := (MaxSpanRunes - utf8.RuneCountInString(match)) / 2
	if room > spanContextRunes {
		room = spanContextRunes
	}
	lo := backRunes(text, start, room)
	hi := forwardRunes(text, end, room)
	s := text[lo:hi]
	if lo > 0 {
		s = "…" + s
	}
	if hi < len(text) {
		s += "…"
	}
	return s
}

func backRunes(s string, from, n int) int {
	for i := 0; i < n && from > 0; i++ {
		_, w := utf8.DecodeLastRuneInString(s[:from])
		from -= w
	}
	return from
}

func forwardRunes(s string, from, n int) int {
	for i := 0; i < n && from < len(s); i++ {
		_, w := utf8.DecodeRuneInString(s[from:])
		from += w
	}
	return from
}

func truncateRunes(s string, n int) string {
	return s[:forwardRunes(s, 0, n)]
}
