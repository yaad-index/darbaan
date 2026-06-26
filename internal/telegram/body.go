package telegram

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"strconv"
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

// attachment is one attachment part: its metadata plus the transfer-decoded
// bytes, so the bot can both list it and upload the real file for inspection.
type attachment struct {
	filename    string
	contentType string
	size        int64
	data        []byte
}

// attachments lists the attachment parts of a raw message so the operator sees
// what they're approving — an attachment is the obvious exfiltration vector. A
// part is an attachment if it is dispositioned attachment, carries a filename,
// or is a non-text leaf (anything but the text/plain + text/html body parts).
func attachments(raw []byte) []attachment {
	ent, _ := gomessage.Read(bytes.NewReader(raw))
	if ent == nil {
		return nil
	}
	var out []attachment
	collectAttachments(ent, &out)
	return out
}

func collectAttachments(ent *gomessage.Entity, out *[]attachment) {
	if mr := ent.MultipartReader(); mr != nil {
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			collectAttachments(p, out)
		}
		return
	}
	att, ok := asAttachment(ent.Header)
	if !ok {
		return
	}
	att.data, _ = io.ReadAll(ent.Body) // transfer-decoded by go-message
	att.size = int64(len(att.data))
	*out = append(*out, att)
}

func asAttachment(h gomessage.Header) (attachment, bool) {
	ct, ctParams, _ := h.ContentType()
	disp, dispParams, _ := h.ContentDisposition()
	filename := dispParams["filename"]
	if filename == "" {
		filename = ctParams["name"]
	}
	// The text/plain + text/html leaves are the body, not attachments — unless
	// explicitly attached or named (e.g. an attached .txt).
	bodyPart := ct == "text/plain" || ct == "text/html" || ct == ""
	if bodyPart && disp != "attachment" && filename == "" {
		return attachment{}, false
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(filename); err == nil && dec != "" {
		filename = dec
	}
	if filename == "" {
		filename = "(unnamed)"
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	return attachment{filename: filename, contentType: ct}, true
}

// humanSize renders a byte count as a short human string (1024-base, e.g.
// "204 KB", "1.2 MB").
func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	val := float64(n)
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	i := -1
	for val >= 1024 && i < len(units)-1 {
		val /= 1024
		i++
	}
	s := strings.TrimSuffix(strconv.FormatFloat(val, 'f', 1, 64), ".0")
	return s + " " + units[i]
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
