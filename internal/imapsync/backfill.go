package imapsync

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// errUnknownValidity reports a record whose UIDVALIDITY is unknown (0) and could
// not be established from a fetch. It is not a mailbox reset: nothing says the
// UID space changed, only that this record never recorded which one it was in.
// The wording matches the write paths' existing refusal (#256, #257).
var errUnknownValidity = errors.New("unconfirmed mailbox validity")

// stampUnknownValidity establishes a zero-validity record's UIDVALIDITY from a real
// fetch of its UID, and persists it (#255). A record predating the persisted field
// reads 0, and every path that needs the UID space (content fetch, keyword and label
// writes) refuses such a record. This is the one place that can lift that refusal,
// and it does so only on evidence, never by inference:
//
//   - the server reports a validity, and it equals the forward-sync cursor's. This is
//     necessary but not sufficient: a reset before the cursor existed would pass it
//     while the UID points at a different message;
//   - the message the server returns for that UID has the same Message-ID as the
//     stored record. This is the check that catches the case above.
//
// A record with no Message-ID has no identity to compare, so it is refused: the
// stored body cannot stand in, because it was sanitized and stamped at write time
// and will never match the upstream bytes. Refusing leaves the record exactly as it
// was. It returns the record as stored afterwards, or errUnknownValidity.
func (s *Syncer) stampUnknownValidity(c *imapclient.Client, serverValidity uint32, m inbound.Message) (inbound.Message, error) {
	if serverValidity == 0 {
		return m, fmt.Errorf("%w: server reported none", errUnknownValidity)
	}
	cursor, err := s.state.Load(s.stateKey())
	if err != nil {
		return m, fmt.Errorf("imapsync: load state: %w", err)
	}
	if cursor.UIDValidity != serverValidity {
		return m, fmt.Errorf("%w: server %d does not match the sync cursor %d", errUnknownValidity, serverValidity, cursor.UIDValidity)
	}
	want := storedMessageID(m)
	if want == "" {
		return m, fmt.Errorf("%w: no Message-ID to identify the record by", errUnknownValidity)
	}
	got, err := fetchMessageID(c, m.UpstreamUID)
	if err != nil {
		return m, err
	}
	if got == "" {
		return m, fmt.Errorf("%w: uid %d returned no message to compare", errUnknownValidity, m.UpstreamUID)
	}
	if got != want {
		return m, fmt.Errorf("%w: uid %d now holds a different message", errUnknownValidity, m.UpstreamUID)
	}
	stamped, err := s.store.StampUIDValidity(m.Owner, m.Inbox, m.ID, serverValidity)
	if err != nil {
		return m, err
	}
	// The store only fills an unknown value, so a validity another writer set in the
	// meantime is kept. Log the stamp only when the stored value is the one this
	// fetch established; a different known value is left for the caller's own
	// validity check, which treats it like any other record.
	if stamped.UIDValidity == serverValidity {
		s.logger.Info("established unknown uidvalidity from an identity-matched fetch",
			"id", m.ID, "uid", m.UpstreamUID, "uidvalidity", stamped.UIDValidity)
	}
	return stamped, nil
}

// storedMessageID is the record's Message-ID, normalized: from the stored envelope,
// which is the same field the server's ENVELOPE returns, or failing that from the
// stored body's header, which sanitizing leaves intact. "" means none is known.
func storedMessageID(m inbound.Message) string {
	if m.Envelope != nil && m.Envelope.MessageID != "" {
		return normalizeMessageID(m.Envelope.MessageID)
	}
	if m.Pending || len(m.Raw) == 0 {
		return ""
	}
	msg, err := mail.ReadMessage(bytes.NewReader(m.Raw))
	if err != nil {
		return ""
	}
	return normalizeMessageID(msg.Header.Get("Message-Id"))
}

// fetchMessageID fetches the ENVELOPE of one UID and returns its normalized
// Message-ID, or "" when the server returned none for it.
func fetchMessageID(c *imapclient.Client, uid uint32) (string, error) {
	var set imap.UIDSet
	set.AddNum(imap.UID(uid))
	msgs, err := c.Fetch(set, &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return "", fmt.Errorf("imapsync: fetch envelope for uid %d: %w", uid, err)
	}
	for _, fm := range msgs {
		if uint32(fm.UID) == uid && fm.Envelope != nil {
			return normalizeMessageID(fm.Envelope.MessageID), nil
		}
	}
	return "", nil
}

// normalizeMessageID strips surrounding whitespace and angle brackets, so the
// envelope's bare form and a header's bracketed form compare equal. The id itself
// is compared exactly: its local part is case-sensitive.
func normalizeMessageID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "<")
	id = strings.TrimSuffix(id, ">")
	return strings.TrimSpace(id)
}

// stampForWrite opens its own session to establish a zero-validity record's
// UIDVALIDITY before a keyword or label write, which both need a known UID space.
// The label writer uses a separate raw connection, so the stamp cannot ride on it.
func (s *Syncer) stampForWrite(m inbound.Message) (inbound.Message, error) {
	// A record with no Message-ID can never be identified, so refuse it before
	// opening a session: a dirty record is retried on every pass, and a dial per
	// pass only to refuse would be pure cost.
	if storedMessageID(m) == "" {
		return m, fmt.Errorf("%w: no Message-ID to identify the record by", errUnknownValidity)
	}
	c, err := s.dial()
	if err != nil {
		return m, fmt.Errorf("imapsync: connect: %w", err)
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()
	sel, err := c.Select(s.mailbox, nil).Wait()
	if err != nil {
		return m, fmt.Errorf("imapsync: select %q: %w", s.mailbox, err)
	}
	return s.stampUnknownValidity(c, sel.UIDValidity, m)
}
