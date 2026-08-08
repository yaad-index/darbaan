package mailtext

import (
	"html"
	"regexp"
	"strings"
)

var (
	// scriptStyleRe drops <script>/<style> element bodies — code, not
	// reader-facing prose. Requires a matching close; an unclosed one falls
	// through to tag stripping, which is inert either way.
	scriptStyleRe = regexp.MustCompile(`(?is)<(script|style)\b[^>]*>.*?</\s*(script|style)\s*>`)
	// blockTagRe turns block-level tags into line breaks so adjacent text does not
	// run together into a single line.
	blockTagRe = regexp.MustCompile(`(?i)</?\s*(br|p|div|li|tr|ul|ol|table|thead|tbody|h[1-6]|blockquote|pre|hr|section|article|header|footer)\b[^>]*>`)
	tagRe      = regexp.MustCompile(`(?s)<[^>]*>`)
	inlineWSRe = regexp.MustCompile(`[ \t\f\v\r]+`)
	lineWSRe   = regexp.MustCompile(`(?m)^[ \t]+|[ \t]+$`)
	multiNLRe  = regexp.MustCompile(`\n{3,}`)
)

// htmlToText flattens HTML to inert plain text. It drops <script>/<style>
// bodies, maps block tags to line breaks, strips every remaining tag, and
// unescapes HTML entities. All other textual content is kept — including text a
// page would hide (display:none, zero-width, off-screen) — because a directive
// hidden from a human reader is exactly what the assessor must see. It never
// executes or fetches anything; it only rewrites the string.
func htmlToText(s string) string {
	s = scriptStyleRe.ReplaceAllString(s, " ")
	s = blockTagRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = inlineWSRe.ReplaceAllString(s, " ")
	s = lineWSRe.ReplaceAllString(s, "")
	s = multiNLRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}
