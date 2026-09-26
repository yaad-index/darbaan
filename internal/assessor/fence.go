package assessor

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// fenceMarker matches a fence begin/end marker in any case, so a mixed-case
// spoof ("[End Untrusted email body]") is neutralized just like the exact-case
// form (C44). It runs on the folded copy built by foldForMarkers, never on the
// raw text.
var fenceMarker = regexp.MustCompile(`(?i)\[(BEGIN|END) UNTRUSTED`)

// Fence wraps untrusted text so it crosses the boundary to the privileged agent
// as clearly-delimited, inert data — never as instructions (the ADR 0006
// principle: attacker text is never echoed as trusted). Any attempt to spoof the
// fence markers inside the payload is neutralized, so the content cannot break
// out of the fence and be read as a command.
//
// The assessor's own machine-consumed output (the factor list and summary) never
// contains attacker text, so it needs no fencing. Fence is for the separate case
// where raw content must accompany a held message for a human to read — that
// content is fenced, marked as quoted data, and kept out of any machine-consumed
// path.
func Fence(label, text string) string {
	label = sanitizeLabel(label)
	begin := "[BEGIN UNTRUSTED " + label + "]"
	end := "[END UNTRUSTED " + label + "]"
	return begin + "\n" + neutralizeMarkers(text) + "\n" + end
}

// neutralizeMarkers rewrites every spoofed fence marker in text so it can no
// longer read as the real frame, to a human or to an LLM summarizing the alert.
// A spoof may hide a marker from a plain match three ways: mixed case, an
// invisible format rune planted inside it (C44), or lookalike characters —
// fullwidth or mathematical forms, or letters from another script (#251).
//
// Matching runs on a folded copy and only the matched span is rewritten in the
// original; every byte outside a marker is left exactly as it arrived. Folding the
// whole text instead would visibly rewrite legitimate content (fullwidth CJK
// punctuation, for instance) just because a spoof appeared somewhere in it.
func neutralizeMarkers(text string) string {
	folded, from, to := foldForMarkers(text)
	matches := fenceMarker.FindAllStringSubmatchIndex(folded, -1)
	if matches == nil {
		return text
	}
	var b strings.Builder
	prev := 0
	for _, m := range matches {
		start, stop := from[m[0]], to[m[1]-1]
		b.WriteString(text[prev:start])
		b.WriteString("[" + folded[m[2]:m[3]] + "_UNTRUSTED")
		prev = stop
	}
	b.WriteString(text[prev:])
	return b.String()
}

// foldForMarkers returns a match-only copy of text in which format runes are
// dropped, each other rune is NFKC-folded (fullwidth, mathematical and circled
// forms, lookalike spaces), and the cross-script lookalikes in markerLookalikes
// map to the ASCII letter they imitate. from[i] and to[i] give the byte range in
// text of the rune that produced folded byte i, so a match on the copy maps back
// to a span of the original.
func foldForMarkers(text string) (folded string, from, to []int) {
	var b strings.Builder
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		var f string
		switch {
		case unicode.Is(unicode.Cf, r):
			// dropped: stripFormatRunes' class, invisible and display-harmless
		case markerLookalikes[r] != 0:
			f = string(markerLookalikes[r])
		default:
			f = norm.NFKC.String(text[i : i+w])
		}
		for range len(f) {
			from = append(from, i)
			to = append(to, i+w)
		}
		b.WriteString(f)
		i += w
	}
	return b.String(), from, to
}

// markerLookalikes maps characters that imitate the fence marker's own alphabet
// ("[", B E G I N D U T R S) to the ASCII they imitate, for the cases NFKC leaves
// alone: letters from other scripts and small capitals. It is deliberately scoped
// to that alphabet. The marker is one fixed token, so a map over its letters
// covers the attack (forging the frame); a general confusables table would buy
// coverage for text nothing compares against.
//
// ⚠️ This is not the full Unicode confusables set (UTS #39). A lookalike absent
// from this map still passes. To extend it, add the rune here with its Unicode
// name in a comment and add a case to TestFenceNeutralizesEveryMappedLookalike.
var markerLookalikes = map[rune]rune{
	'\u27E6': '[', // MATHEMATICAL LEFT WHITE SQUARE BRACKET
	'\u2045': '[', // LEFT SQUARE BRACKET WITH QUILL
	'\u298B': '[', // LEFT SQUARE BRACKET WITH UNDERBAR
	'\u298D': '[', // LEFT SQUARE BRACKET WITH TICK IN TOP CORNER
	'\u298F': '[', // LEFT SQUARE BRACKET WITH TICK IN BOTTOM CORNER

	'\u0412': 'B', // CYRILLIC CAPITAL LETTER VE
	'\u0432': 'B', // CYRILLIC SMALL LETTER VE
	'\u0392': 'B', // GREEK CAPITAL LETTER BETA
	'\u0299': 'B', // LATIN LETTER SMALL CAPITAL B
	'\u13F4': 'B', // CHEROKEE LETTER YV

	'\u0415': 'E', // CYRILLIC CAPITAL LETTER IE
	'\u0435': 'E', // CYRILLIC SMALL LETTER IE
	'\u0395': 'E', // GREEK CAPITAL LETTER EPSILON
	'\u1D07': 'E', // LATIN LETTER SMALL CAPITAL E
	'\u13AC': 'E', // CHEROKEE LETTER GV

	'\u050C': 'G', // CYRILLIC CAPITAL LETTER KOMI SJE
	'\u0261': 'G', // LATIN SMALL LETTER SCRIPT G
	'\u0262': 'G', // LATIN LETTER SMALL CAPITAL G
	'\u13C0': 'G', // CHEROKEE LETTER NAH

	'\u0406': 'I', // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
	'\u0456': 'I', // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
	'\u04C0': 'I', // CYRILLIC LETTER PALOCHKA
	'\u04CF': 'I', // CYRILLIC SMALL LETTER PALOCHKA
	'\u0399': 'I', // GREEK CAPITAL LETTER IOTA
	'\u03B9': 'I', // GREEK SMALL LETTER IOTA
	'\u0131': 'I', // LATIN SMALL LETTER DOTLESS I
	'\u026A': 'I', // LATIN LETTER SMALL CAPITAL I

	'\u039D': 'N', // GREEK CAPITAL LETTER NU
	'\u0274': 'N', // LATIN LETTER SMALL CAPITAL N

	'\u0500': 'D', // CYRILLIC CAPITAL LETTER KOMI DE
	'\u0501': 'D', // CYRILLIC SMALL LETTER KOMI DE
	'\u1D05': 'D', // LATIN LETTER SMALL CAPITAL D
	'\u13A0': 'D', // CHEROKEE LETTER A

	'\u054D': 'U', // ARMENIAN CAPITAL LETTER SEH
	'\u057D': 'U', // ARMENIAN SMALL LETTER SEH
	'\u1D1C': 'U', // LATIN LETTER SMALL CAPITAL U

	'\u0422': 'T', // CYRILLIC CAPITAL LETTER TE
	'\u0442': 'T', // CYRILLIC SMALL LETTER TE
	'\u03A4': 'T', // GREEK CAPITAL LETTER TAU
	'\u1D1B': 'T', // LATIN LETTER SMALL CAPITAL T
	'\u13A2': 'T', // CHEROKEE LETTER I

	'\u0280': 'R', // LATIN LETTER SMALL CAPITAL R
	'\u13A1': 'R', // CHEROKEE LETTER E

	'\u0405': 'S', // CYRILLIC CAPITAL LETTER DZE
	'\u0455': 'S', // CYRILLIC SMALL LETTER DZE
	'\uA731': 'S', // LATIN LETTER SMALL CAPITAL S
	'\u13DA': 'S', // CHEROKEE LETTER DU
}

// sanitizeLabel keeps the (trusted, caller-supplied) label from carrying line
// breaks or bracket characters that would disturb the fence framing.
func sanitizeLabel(label string) string {
	label = strings.NewReplacer("\n", " ", "\r", " ", "[", "(", "]", ")").Replace(label)
	label = strings.TrimSpace(label)
	if label == "" {
		return "content"
	}
	return label
}
