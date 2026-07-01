package admin

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sort"

	"github.com/emersion/go-message/textproto"

	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// ErrUnknownInbox is returned by ApproveAs when the requested inbox is not a
// configured inbox with a send identity.
var ErrUnknownInbox = errors.New("admin: unknown inbox (no configured send identity)")

// InboxIdentity pairs a configured inbox name with its send identity (ADR 0023).
type InboxIdentity struct {
	Name     string `json:"name"`
	Identity string `json:"identity"`
}

// SetInboxIdentities installs the per-inbox send identities (ADR 0023 slice 5):
// the identities the operator may re-pick at approval time, and the address
// ApproveAs rewrites From to. serve builds it from the configured inboxes; only
// inboxes with a non-empty identity are eligible.
func (s *Service) SetInboxIdentities(m map[string]string) { s.identities = m }

// Inboxes lists the configured inboxes that have a send identity (ADR 0023 slice
// 5), sorted by name — the operator's Change-sender choices.
func (s *Service) Inboxes() []InboxIdentity {
	out := make([]InboxIdentity, 0, len(s.identities))
	for name, id := range s.identities {
		if id != "" {
			out = append(out, InboxIdentity{Name: inbound.NormInbox(name), Identity: id})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sendBody returns the bytes that would be sent for a message: the human-amended
// body if one was released (ADR 0004), else the original raw.
func sendBody(m sluice.Message) []byte {
	if m.Released != nil {
		return m.Released
	}
	return m.Raw
}

// rewriteFrom returns raw with its From header replaced by identity, preserving
// the message BODY byte-for-byte (ADR 0025): it re-reads only the header block via
// textproto, sets From, then re-appends the original body untouched — no MIME
// re-encode, so attachments/structure are unchanged.
func rewriteFrom(raw []byte, identity string) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	hdr, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, err
	}
	hdr.Set("From", identity)
	var buf bytes.Buffer
	if err := textproto.WriteHeader(&buf, hdr); err != nil {
		return nil, err
	}
	if _, err := io.Copy(&buf, br); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
