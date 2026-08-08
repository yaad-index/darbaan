package mailtext

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// blockElements map to a line break so adjacent block text does not run together.
var blockElements = map[string]bool{
	"br": true, "p": true, "div": true, "li": true, "tr": true,
	"ul": true, "ol": true, "table": true, "thead": true, "tbody": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"blockquote": true, "pre": true, "hr": true,
	"section": true, "article": true, "header": true, "footer": true,
}

var (
	inlineWSRe = regexp.MustCompile(`[ \t\f\v\r]+`)
	lineWSRe   = regexp.MustCompile(`(?m)^[ \t]+|[ \t]+$`)
	multiNLRe  = regexp.MustCompile(`\n{3,}`)
)

// htmlToText flattens HTML to inert plain text with an HTML tokenizer. It
// collects text tokens, drops the data of <script>/<style> elements by
// construction (the tokenizer emits their body as raw text between the start and
// end tag; it is skipped, not matched), and maps block-level tags to line breaks.
// All other textual content is kept — including text a page would hide
// (display:none, zero-width, off-screen) — because a directive concealed from a
// human reader is exactly the vector the assessor must see. It tokenizes only; it
// never renders, executes, or fetches anything.
func htmlToText(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	var b strings.Builder
	skip := 0 // >0 while inside a <script>/<style> element
	for {
		switch z.Next() {
		case html.ErrorToken:
			// io.EOF or a parse fault ends the stream; text collected so far is kept.
			return normalizeWS(b.String())
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text()) // tokenizer returns entity-unescaped text
			}
		case html.StartTagToken:
			name, _ := z.TagName()
			switch tag := strings.ToLower(string(name)); {
			case tag == "script" || tag == "style":
				skip++
			case blockElements[tag]:
				b.WriteByte('\n')
			}
		case html.SelfClosingTagToken:
			name, _ := z.TagName()
			if blockElements[strings.ToLower(string(name))] {
				b.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch tag := strings.ToLower(string(name)); {
			case (tag == "script" || tag == "style") && skip > 0:
				skip--
			case blockElements[tag]:
				b.WriteByte('\n')
			}
		}
	}
}

// normalizeWS collapses inline whitespace runs, trims per-line padding, and caps
// consecutive blank lines, leaving readable text for the assessor.
func normalizeWS(s string) string {
	s = inlineWSRe.ReplaceAllString(s, " ")
	s = lineWSRe.ReplaceAllString(s, "")
	s = multiNLRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}
