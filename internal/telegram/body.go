package telegram

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register charsets so non-UTF-8 bodies decode
	gomail "github.com/emersion/go-message/mail"
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

// headerAddrs parses the human display form of the From and To/Cc headers
// (RFC 2047-decoded "Name <addr>") and the lower-cased set of header recipient
// addresses (for the hidden-recipient check). parsed is false when the message
// can't be read — so a fetch/parse failure never false-flags every recipient.
func headerAddrs(raw []byte) (from, to string, headerSet map[string]bool, parsed bool) {
	headerSet = map[string]bool{}
	if len(raw) == 0 {
		return "", "", headerSet, false
	}
	ent, _ := gomessage.Read(bytes.NewReader(raw))
	if ent == nil {
		return "", "", headerSet, false
	}
	h := gomail.Header{Header: ent.Header}
	from = addrDisplay(addrList(h, "From"))

	var rcpts []*gomail.Address
	rcpts = append(rcpts, addrList(h, "To")...)
	rcpts = append(rcpts, addrList(h, "Cc")...)
	parts := make([]string, 0, len(rcpts))
	for _, a := range rcpts {
		parts = append(parts, formatAddr(a))
		headerSet[strings.ToLower(a.Address)] = true
	}
	return from, strings.Join(parts, ", "), headerSet, true
}

func addrList(h gomail.Header, key string) []*gomail.Address {
	as, err := h.AddressList(key)
	if err != nil {
		return nil
	}
	return as
}

func addrDisplay(as []*gomail.Address) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, formatAddr(a))
	}
	return strings.Join(parts, ", ")
}

// formatAddr renders an address as "Name <addr>" (decoded name) or bare address.
func formatAddr(a *gomail.Address) string {
	if a.Name != "" {
		return fmt.Sprintf("%s <%s>", a.Name, a.Address)
	}
	return a.Address
}

// hiddenRcpts returns the envelope recipients not present in the header To/Cc —
// the Bcc/hidden recipients the operator would otherwise approve unseen.
func hiddenRcpts(envelope []string, headerSet map[string]bool) []string {
	var hidden []string
	for _, r := range envelope {
		if !headerSet[strings.ToLower(strings.TrimSpace(r))] {
			hidden = append(hidden, r)
		}
	}
	return hidden
}
