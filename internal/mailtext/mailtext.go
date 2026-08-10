// Package mailtext extracts the decoded, inert text an injection assessor reads
// from an incoming message (ADR 0032 slice 2). It is a pure, bounded transform:
// raw RFC 822 bytes in, assessable text out. It never executes, renders, or
// fetches anything — it only decodes transfer-encoding and charset (via
// go-message) and strips markup.
//
// Two deliberate choices shape it, both driven by the threat model:
//
//   - It extracts *every* text variant, not the one a mail client would display.
//     A multipart/alternative can carry benign text/plain and a hidden directive
//     in its text/html sibling; a human client shows one, so the assessor must
//     see both. Extraction includes more, never less.
//   - HTML is flattened to text with all textual content kept, including text a
//     page would hide (display:none, zero-width, off-screen). Hiding directives
//     from a human reader is exactly the vector the assessor must catch, so
//     nothing is dropped for being "invisible"; only <script>/<style> element
//     bodies (code, not reader-facing prose) are removed.
//
// Extraction is bounded (per-part and total byte caps, a part-count cap, and a
// recursion-depth cap) so a hostile message cannot exhaust memory, and inert (no
// active content is ever executed).
package mailtext

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register charsets so non-UTF-8 bodies decode
)

// Content is the extracted, assessable text of a message.
type Content struct {
	// Body is the concatenated decoded text of the message's body parts
	// (text/plain kept as-is, text/html flattened to text), all variants included.
	Body string
	// Attachments describes each attachment part: its metadata and, for text-typed
	// attachments within the limits, the extracted inert text (a named injection
	// vector). Binary attachments (e.g. PDF, images) carry metadata only in v1;
	// their decoders are a follow-up.
	Attachments []Attachment
	// Truncated is true if any cap (per-part, total, part-count, or depth) was hit,
	// so a caller knows the extraction is bounded — the content it holds is real,
	// there is just more of it beyond the limits.
	Truncated bool
	// Undecodable is true if a part could not be decoded or read at all, or the MIME
	// structure errored mid-stream, so text the message carries never reached the
	// assessor (C19/C20). Unlike Truncated (a benign bound on readable content), this
	// is an extraction hard-fail: the caller must not clear the message on it — the
	// assessor cannot vouch for content it never saw (ADR 0032 fail-safe, Amendment 1).
	Undecodable bool
}

// Attachment is one attachment part.
type Attachment struct {
	Filename    string
	ContentType string
	Size        int64  // decoded bytes seen, bounded by the per-part cap
	Text        string // extracted inert text (text-typed attachments only)
	Extracted   bool   // whether Text was populated
}

// Limits bounds extraction. Zero fields take DefaultLimits values.
type Limits struct {
	MaxPartText  int // max decoded bytes read from any single part
	MaxTotalText int // max total extracted text bytes kept across the message
	MaxParts     int // max leaf parts to process
	MaxDepth     int // max multipart nesting depth to descend
}

// DefaultLimits are the v1 extraction bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxPartText:  256 * 1024,
		MaxTotalText: 1024 * 1024,
		MaxParts:     200,
		MaxDepth:     20,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxPartText <= 0 {
		l.MaxPartText = d.MaxPartText
	}
	if l.MaxTotalText <= 0 {
		l.MaxTotalText = d.MaxTotalText
	}
	if l.MaxParts <= 0 {
		l.MaxParts = d.MaxParts
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}

// Extract parses raw and returns its assessable text. It is best-effort within
// the message: an unreadable part is skipped, not fatal. It returns an error
// only when the message cannot be parsed at all — the caller's fail-safe (an
// unreadable message is not cleared) lives in the orchestration layer.
func Extract(raw []byte, lim Limits) (Content, error) {
	if len(raw) == 0 {
		return Content{}, fmt.Errorf("mailtext: empty message")
	}
	ent, err := gomessage.Read(bytes.NewReader(raw))
	if ent == nil {
		if err != nil {
			return Content{}, fmt.Errorf("mailtext: parse message: %w", err)
		}
		return Content{}, fmt.Errorf("mailtext: unreadable message")
	}
	st := &walkState{lim: lim.withDefaults()}
	if err != nil {
		// go-message returns a usable entity alongside a non-nil error for a soft
		// decode failure — an unknown charset or transfer-encoding — where the body
		// is only available raw/undecoded (C20). The assessor's decoded view is then
		// unreliable, so flag the extraction undecodable; the caller holds fail-safe.
		st.undecodable = true
	}
	st.walk(ent, 0)
	return Content{
		Body:        strings.TrimSpace(st.body.String()),
		Attachments: st.atts,
		Truncated:   st.truncated,
		Undecodable: st.undecodable,
	}, nil
}

type walkState struct {
	lim         Limits
	parts       int
	totalText   int
	truncated   bool
	undecodable bool
	body        strings.Builder
	atts        []Attachment
}

func (st *walkState) walk(ent *gomessage.Entity, depth int) {
	if depth > st.lim.MaxDepth {
		st.truncated = true
		return
	}
	if mr := ent.MultipartReader(); mr != nil {
		for {
			p, err := mr.NextPart()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break // normal end of the part stream
				}
				// Any other error is an extraction hard-fail, flagged either way
				// (C19/C20): a structural break (p == nil) skips every remaining part
				// unseen, so stop; a soft decode error (unknown charset/encoding) still
				// yields a usable part, so keep processing it and the rest rather than
				// abandoning readable siblings on one bad part.
				st.undecodable = true
				if p == nil {
					break
				}
			}
			st.walk(p, depth+1)
		}
		return
	}
	st.parts++
	if st.parts > st.lim.MaxParts {
		st.truncated = true
		return
	}
	st.leaf(ent, depth)
}

func (st *walkState) leaf(ent *gomessage.Entity, depth int) {
	ct, ctParams, _ := ent.Header.ContentType()
	ct = strings.ToLower(strings.TrimSpace(ct))
	disp, dispParams, _ := ent.Header.ContentDisposition()
	filename := attachmentFilename(dispParams, ctParams)

	// A message/rfc822 part carries a whole nested message; a directive smuggled in
	// an attached .eml must be scanned, not left opaque (C38). Record it as an
	// attachment for visibility, then recurse into the embedded message so its body
	// and attachments feed the same detectors. The depth cap bounds the recursion.
	if ct == "message/rfc822" {
		raw, capped, failed := st.readCapped(ent.Body)
		if capped {
			st.truncated = true
		}
		if failed {
			st.undecodable = true
		}
		st.atts = append(st.atts, Attachment{
			Filename:    attachmentDisplayName(filename),
			ContentType: attachmentContentType(ct),
			Size:        int64(len(raw)),
		})
		nested, nerr := gomessage.Read(strings.NewReader(raw))
		if nested == nil {
			st.undecodable = true // an embedded message we cannot parse hides its content
			return
		}
		if nerr != nil {
			st.undecodable = true // soft decode error on the embedded message
		}
		st.walk(nested, depth+1)
		return
	}

	// A text/plain or text/html leaf with no attachment disposition and no
	// filename is a body part; everything else (attached, named, or non-text) is
	// an attachment.
	isBodyType := ct == "text/plain" || ct == "text/html" || ct == ""
	if isBodyType && disp != "attachment" && filename == "" {
		raw, capped, failed := st.readCapped(ent.Body)
		if capped {
			st.truncated = true
		}
		if failed {
			st.undecodable = true // a body part that would not decode never reached the assessor (C20)
		}
		text := raw
		if ct == "text/html" {
			text = htmlToText(raw)
		}
		st.appendBody(text)
		return
	}

	raw, capped, failed := st.readCapped(ent.Body)
	if capped {
		st.truncated = true
	}
	if failed {
		st.undecodable = true // an attachment that would not decode never reached the assessor (C20)
	}
	a := Attachment{
		Filename:    attachmentDisplayName(filename),
		ContentType: attachmentContentType(ct),
		Size:        int64(len(raw)),
	}
	if strings.HasPrefix(ct, "text/") {
		text := raw
		if ct == "text/html" {
			text = htmlToText(raw)
		}
		a.Text = st.budgetText(text)
		a.Extracted = true
	}
	st.atts = append(st.atts, a)
}

// appendBody adds body text within the total budget.
func (st *walkState) appendBody(text string) {
	text = st.budgetText(text)
	if text == "" {
		return
	}
	if st.body.Len() > 0 {
		st.body.WriteString("\n\n")
	}
	st.body.WriteString(text)
}

// budgetText trims text to the remaining total-text budget, tracks the spend,
// and flags truncation if it had to cut.
func (st *walkState) budgetText(text string) string {
	remaining := st.lim.MaxTotalText - st.totalText
	if remaining <= 0 {
		if text != "" {
			st.truncated = true
		}
		return ""
	}
	if len(text) > remaining {
		text = text[:remaining]
		st.truncated = true
	}
	st.totalText += len(text)
	return text
}

// readCapped reads at most MaxPartText bytes from a part body, reporting the two
// incompleteness modes separately: capped is a benign per-part cap hit (the bytes
// it returns are real, there are just more), while failed is a genuine read/decode
// error — go-message decodes transfer-encoding and charset here, so a bogus
// charset= surfaces as failed with the text never seen (C20). The caller flags a
// cap as Truncated but a failure as Undecodable, so a hard-fail can hold while a
// bounded read does not.
func (st *walkState) readCapped(r io.Reader) (text string, capped, failed bool) {
	limit := st.lim.MaxPartText
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	// Report the cap hit and the read error independently: io.ReadAll can return
	// limit+1 bytes AND a non-nil error in one call, so collapsing them on the cap
	// path would drop a genuine decode failure that happened at the same read.
	return string(b[:min(len(b), limit)]), len(b) > limit, err != nil
}

func attachmentFilename(dispParams, ctParams map[string]string) string {
	if f := dispParams["filename"]; f != "" {
		return f
	}
	return ctParams["name"]
}

func attachmentDisplayName(filename string) string {
	if dec, err := new(mime.WordDecoder).DecodeHeader(filename); err == nil && dec != "" {
		filename = dec
	}
	if filename == "" {
		return "(unnamed)"
	}
	return filename
}

func attachmentContentType(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}
