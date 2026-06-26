package telegram

import (
	"bytes"
	"io"
	"strings"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register charsets so non-UTF-8 bodies decode
)

// bodyText extracts the decoded text/plain body from a raw message so the
// operator can review what they're approving. Best-effort: returns "" when the
// message has no text part or can't be parsed (the notification still shows the
// headers). go-message decodes the transfer-encoding and charset transparently.
func bodyText(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	ent, _ := gomessage.Read(bytes.NewReader(raw))
	if ent == nil {
		return ""
	}
	return strings.TrimRight(extractText(ent), " \t\r\n")
}

// extractText returns the first text/plain content in an entity, descending
// into nested multiparts (e.g. multipart/alternative inside multipart/mixed).
func extractText(ent *gomessage.Entity) string {
	mr := ent.MultipartReader()
	if mr == nil {
		ct, _, _ := ent.Header.ContentType()
		if strings.HasPrefix(ct, "text/") {
			b, _ := io.ReadAll(ent.Body)
			return string(b)
		}
		return ""
	}
	var nested string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		ct, _, _ := p.Header.ContentType()
		switch {
		case ct == "text/plain":
			b, _ := io.ReadAll(p.Body)
			return string(b)
		case strings.HasPrefix(ct, "multipart/"):
			if s := extractText(p); s != "" && nested == "" {
				nested = s // keep as a fallback if no top-level text/plain turns up
			}
		}
	}
	return nested
}
