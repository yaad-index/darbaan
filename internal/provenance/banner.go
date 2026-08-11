package provenance

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"regexp"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// Banner fence markers — a PEM-style ASCII fence, recognizable and
// encoding-safe, so an existing banner can be detected and replaced (not
// stacked) when a body is re-materialized (ADR 0030 slice 4).
const (
	bannerBegin = "-----BEGIN DARBAAN TRUST BANNER-----"
	bannerEnd   = "-----END DARBAAN TRUST BANNER-----"
)

// maybeBanner prepends the advisory trust banner to a top-level text/plain body,
// or returns body unchanged for any other shape (headers-only, never an error).
// The banner is default-off and belt-and-suspenders; the X-Darbaan-* headers are
// the authoritative signal and ship on every message regardless of MIME shape,
// so skipping the banner here loses no trust information. v1 deliberately does
// NOT touch multipart or other nested MIME — that is a separate slice.
func maybeBanner(hdr textproto.Header, body []byte, s Stamp) []byte {
	if !bannerableText(hdr) {
		return body
	}
	decoded, encode, ok := decodeText(body, hdr.Get("Content-Transfer-Encoding"))
	if !ok {
		return body
	}
	return encode(applyBanner(decoded, s))
}

// bannerableText reports whether hdr describes a top-level text/plain body in an
// ASCII-compatible charset — the only shape v1 banners. A missing Content-Type
// defaults to text/plain per RFC 2045. A non-ASCII-superset charset is skipped
// so an ASCII banner can't corrupt the encoding.
func bannerableText(hdr textproto.Header) bool {
	ct := strings.TrimSpace(hdr.Get("Content-Type"))
	if ct == "" {
		return true
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "text/plain" {
		return false
	}
	switch strings.ToLower(params["charset"]) {
	case "", "us-ascii", "ascii", "utf-8", "utf8", "iso-8859-1", "latin1", "windows-1252":
		return true
	default:
		return false
	}
}

// decodeText decodes body per its Content-Transfer-Encoding and returns a
// matching re-encoder. An unknown or undecodable encoding returns ok=false, so
// the caller keeps the body untouched (headers-only) rather than risk corrupting
// it.
func decodeText(body []byte, cte string) (decoded []byte, encode func([]byte) []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "", "7bit", "8bit", "binary":
		return body, func(b []byte) []byte { return b }, true
	case "quoted-printable":
		dec, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, nil, false
		}
		return dec, encodeQP, true
	case "base64":
		dec, err := base64.StdEncoding.DecodeString(stripASCIISpace(body))
		if err != nil {
			return nil, nil, false
		}
		return dec, encodeBase64, true
	default:
		return nil, nil, false
	}
}

func encodeQP(b []byte) []byte {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// encodeBase64 encodes b as base64 wrapped at 76 columns with CRLF, per MIME.
func encodeBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var buf bytes.Buffer
	for len(enc) > 76 {
		buf.WriteString(enc[:76])
		buf.WriteString("\r\n")
		enc = enc[76:]
	}
	buf.WriteString(enc)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// stripASCIISpace removes ASCII whitespace so a line-wrapped base64 body decodes.
func stripASCIISpace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// applyBanner strips any darbaan banner already at the top of body, then prepends
// a fresh one — so re-running on an already-bannered body replaces rather than
// stacks (idempotent).
func applyBanner(body []byte, s Stamp) []byte {
	// Order matters: strip our own leading banner first (an exact-case match that keeps
	// applying idempotent), THEN neutralize any forged marker left in the body. Running
	// the neutralizer first would defang our genuine leading banner too, and the
	// exact-case strip would then find nothing to remove.
	body = stripBanner(body)
	body = neutralizeBanners(body)
	block := bannerBlock(s)
	out := make([]byte, 0, len(block)+len(body))
	out = append(out, block...)
	out = append(out, body...)
	return out
}

// bannerBlock renders the advisory banner: it reproduces the trust (and note, if
// any) the X-Darbaan-* headers carry, with an explicit line that the headers —
// not this banner — are authoritative.
func bannerBlock(s Stamp) []byte {
	var b bytes.Buffer
	b.WriteString(bannerBegin)
	b.WriteString("\r\n")
	b.WriteString(TrustHeader + ": " + s.Trust + "\r\n")
	if s.Note != "" {
		b.WriteString(NoteHeader + ": " + headerSafe(s.Note) + "\r\n")
	}
	b.WriteString("This banner is advisory; the X-Darbaan-* headers are authoritative.\r\n")
	b.WriteString(bannerEnd)
	b.WriteString("\r\n\r\n")
	return b.Bytes()
}

// stripBanner removes a darbaan banner block from the very top of body, consuming
// exactly the block and the single blank-line separator bannerBlock writes — so
// stripping our own banner is the exact inverse of applying it and a re-run is a
// byte-level no-op. Only the LEADING block is removed, by an exact-case prefix match.
// A forged banner deeper in the body is deliberately NOT deleted here: deleting an
// interior block would splice its neighbours into a fresh marker (worse than doing
// nothing — the attacker needs a banner accepted at offset 0 and the delete would
// build it), and would excise a legitimately quoted banner such as a forwarded
// darbaan message. Interior forgeries are defanged by neutralizeBanners instead. A
// body that doesn't begin with the banner, or whose marker is unterminated, is
// returned unchanged.
func stripBanner(body []byte) []byte {
	if !bytes.HasPrefix(body, []byte(bannerBegin)) {
		return body
	}
	i := bytes.Index(body, []byte(bannerEnd))
	if i < 0 {
		return body
	}
	rest := body[i+len(bannerEnd):]
	return bytes.TrimPrefix(rest, []byte("\r\n\r\n"))
}

// cfTolerant returns a regexp source matching lit with any run of Unicode format (Cf)
// runes permitted between each of its characters — so a marker an attacker splits with
// invisible runes (a zero-width space inside "BANNER") still matches in the RAW body.
// Each literal character is regexp-quoted.
func cfTolerant(lit string) string {
	var b strings.Builder
	for i, r := range lit {
		if i > 0 {
			b.WriteString(`\p{Cf}*`)
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	return b.String()
}

// bannerBeginMarker / bannerEndMarker match a darbaan banner begin/end marker in any
// case, tolerant of Cf runes interleaved between characters. The tolerance is in the
// MATCHING, not the body: unlike assessor.Fence — which strips Cf from a match-only
// copy it then discards — this text IS the delivered message, so nothing may be
// deleted from it. neutralizeBanners rewrites only the matched marker span (any Cf
// runes inside the marker go with it); Cf runes elsewhere in the body (a joined-emoji
// ZWJ, the bidi controls that order RTL text) are left untouched.
var (
	bannerBeginMarker = regexp.MustCompile(`(?i)` + cfTolerant(bannerBegin))
	bannerEndMarker   = regexp.MustCompile(`(?i)` + cfTolerant(bannerEnd))
)

// The defanged forms neutralizeBanners writes over a forged marker: bannerBegin /
// bannerEnd with " (UNTRUSTED)" before the closing dashes. They no longer match the
// markers above (the closing dashes no longer follow "BANNER"), so a second pass
// rewrites nothing — neutralization is idempotent.
const (
	bannerBeginDefanged = "-----BEGIN DARBAAN TRUST BANNER (UNTRUSTED)-----"
	bannerEndDefanged   = "-----END DARBAAN TRUST BANNER (UNTRUSTED)-----"
)

// neutralizeBanners defangs every darbaan banner marker left in body — a forgery an
// attacker planted, the genuine leading banner having already been removed by
// stripBanner. It REWRITES each marker in place, never deletes: no bytes outside the
// matched marker span are removed, so a quoted banner in a forwarded message keeps its
// surrounding content, no deletion can splice two fragments into a fresh marker, and
// format runes elsewhere in the body (emoji ZWJ, RTL bidi controls) are preserved.
// Matching is case-insensitive and tolerant of Cf runes interleaved into a marker.
func neutralizeBanners(body []byte) []byte {
	body = bannerBeginMarker.ReplaceAllLiteral(body, []byte(bannerBeginDefanged))
	body = bannerEndMarker.ReplaceAllLiteral(body, []byte(bannerEndDefanged))
	return body
}
