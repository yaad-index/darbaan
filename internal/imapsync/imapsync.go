package imapsync

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// DialFunc opens a logged-in client to the upstream IMAP server. It is injected
// so the engine can be tested against an in-process server; production builds it
// from config (TLS dial + login) — see Dialer.
type DialFunc func() (*imapclient.Client, error)

// Syncer pulls new messages from one upstream mailbox into the inbound store.
type Syncer struct {
	dial    DialFunc
	mailbox string
	owner   string // the agent whose mailbox this is
	store   inbound.InboundStore
	state   StateStore
}

// New builds a Syncer. owner is the agent the synced mail belongs to.
func New(dial DialFunc, mailbox, owner string, store inbound.InboundStore, state StateStore) *Syncer {
	return &Syncer{dial: dial, mailbox: mailbox, owner: owner, store: store, state: state}
}

// Dialer is the production DialFunc: TLS-connect to addr and log in with the
// Darbaan-held upstream credentials. The connection is exercised live (Inc 2);
// the engine is tested with an injected DialFunc.
func Dialer(addr, username, password string) DialFunc {
	return func() (*imapclient.Client, error) {
		c, err := imapclient.DialTLS(addr, nil)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
		if err := c.Login(username, password).Wait(); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("login: %w", err)
		}
		return c, nil
	}
}

// Sync runs one incremental pull: SELECT the mailbox, UID-FETCH the ENVELOPE of
// everything newer than the stored cursor, store each headers-only (pending) via
// inbound.AddSyncedPending, and advance the cursor. Bodies are fetched on demand
// (FetchContent) when first read. A UIDVALIDITY change resets the cursor and
// re-syncs from scratch. The upstream is read-only (no flag/delete write-back,
// v1). Returns the count stored this run.
func (s *Syncer) Sync(ctx context.Context) (int, error) {
	c, err := s.dial()
	if err != nil {
		return 0, fmt.Errorf("imapsync: connect: %w", err)
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()

	sel, err := c.Select(s.mailbox, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("imapsync: select %q: %w", s.mailbox, err)
	}

	loaded, err := s.state.Load(s.mailbox)
	if err != nil {
		return 0, err
	}
	last := loaded.LastUID
	if loaded.UIDValidity != sel.UIDValidity {
		last = 0 // new or reset mailbox — full re-sync
	}

	stored, highest, err := s.pull(c, sel.UIDValidity, uint32(sel.UIDNext), last)
	if err != nil {
		return stored, err
	}

	newState := State{UIDValidity: sel.UIDValidity, LastUID: highest}
	if newState != loaded {
		if err := s.state.Save(s.mailbox, newState); err != nil {
			return stored, err
		}
	}
	return stored, nil
}

// pull fetches new messages and stores them, returning the count stored and the
// new cursor (the highest UID stored, or the prior cursor if nothing was new).
//
// It uses a CONCRETE upper bound from the mailbox's UIDNEXT — go-imap's dynamic
// "*" range (Stop 0) is mis-encoded on the wire against strict servers (e.g.
// Gmail) and silently matches nothing; only when a server reports no UIDNEXT do
// we fall back to the dynamic range, guarded against the "N:*" past-the-end
// re-return.
//
// The fetch is STREAMED (one message buffered at a time via cmd.Next), so a
// large mailbox never loads into memory at once. On a mid-stream error the
// cursor is not advanced, so the next run re-syncs — at-least-once, no gaps.
func (s *Syncer) pull(c *imapclient.Client, uidValidity, uidNext, last uint32) (int, uint32, error) {
	var set imap.UIDSet
	if uidNext > 0 {
		hi := uidNext - 1 // highest possible existing UID
		if last+1 > hi {
			return 0, last, nil // no new messages
		}
		set.AddRange(imap.UID(last+1), imap.UID(hi))
	} else {
		set.AddRange(imap.UID(last+1), 0) // fallback: dynamic "*"
	}

	// Headers-only: ENVELOPE + RFC822.SIZE (stored as metadata so the read face
	// serves FETCH ENVELOPE / RFC822Size / header SEARCH without the body) but no
	// BODY[] — the body is fetched on demand when first read (lazy, ADR 0019).
	cmd := c.Fetch(set, &imap.FetchOptions{
		UID:        true,
		Envelope:   true,
		RFC822Size: true,
	})

	stored, highest := 0, last
	for {
		data := cmd.Next()
		if data == nil {
			break
		}
		m, err := data.Collect()
		if err != nil {
			_ = cmd.Close()
			return stored, highest, fmt.Errorf("imapsync: fetch: %w", err)
		}
		uid := uint32(m.UID)
		if uid <= last {
			continue // dynamic "N:*" past-the-end guard
		}
		d := deliveryOf(s.owner, m)
		d.UpstreamUID = uid
		d.UIDValidity = uidValidity
		// Store headers-only (pending); the body is fetched on demand. Idempotent
		// on (owner, UIDVALIDITY, UID): a re-fetched message is a no-op.
		added, _, err := s.store.AddSyncedPending(d)
		if err != nil {
			_ = cmd.Close()
			return stored, highest, fmt.Errorf("imapsync: store uid %d: %w", uid, err)
		}
		if added {
			stored++
		}
		// Advance the cursor past every fetched UID, new or already-stored.
		if uid > highest {
			highest = uid
		}
	}
	if err := cmd.Close(); err != nil {
		return stored, highest, fmt.Errorf("imapsync: fetch: %w", err)
	}
	return stored, highest, nil
}

// FetchContent fills a pending message's body on demand (ADR 0019, the read-time
// half): it dials upstream, fetches that message's body by its stored UID, and
// SetContents it (marking the record present). A present message is returned
// as-is without contacting upstream — content is fetched once, then cached. It
// errors cleanly when the mailbox UIDVALIDITY has changed (the stored UID is
// stale) or the message is gone upstream, so the read face can surface a
// transient error rather than empty content.
func (s *Syncer) FetchContent(owner, id string) (inbound.Message, error) {
	m, err := s.store.Get(owner, id)
	if err != nil {
		return inbound.Message{}, err
	}
	if !m.Pending {
		return m, nil // already present — no upstream contact
	}

	c, err := s.dial()
	if err != nil {
		return inbound.Message{}, fmt.Errorf("imapsync: connect: %w", err)
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()

	sel, err := c.Select(s.mailbox, nil).Wait()
	if err != nil {
		return inbound.Message{}, fmt.Errorf("imapsync: select %q: %w", s.mailbox, err)
	}
	if sel.UIDValidity != m.UIDValidity {
		return inbound.Message{}, fmt.Errorf("imapsync: content for %s unavailable: mailbox reset (uidvalidity %d != %d)", id, sel.UIDValidity, m.UIDValidity)
	}

	var set imap.UIDSet
	set.AddNum(imap.UID(m.UpstreamUID))
	cmd := c.Fetch(set, &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	})
	var raw []byte
	for {
		data := cmd.Next()
		if data == nil {
			break
		}
		fm, err := data.Collect()
		if err != nil {
			_ = cmd.Close()
			return inbound.Message{}, fmt.Errorf("imapsync: fetch content %s: %w", id, err)
		}
		if uint32(fm.UID) == m.UpstreamUID {
			raw = rawBody(fm)
		}
	}
	if err := cmd.Close(); err != nil {
		return inbound.Message{}, fmt.Errorf("imapsync: fetch content %s: %w", id, err)
	}
	if raw == nil {
		return inbound.Message{}, fmt.Errorf("imapsync: content for %s unavailable: upstream uid %d not found", id, m.UpstreamUID)
	}
	return s.store.SetContent(owner, id, raw)
}

func deliveryOf(owner string, m *imapclient.FetchMessageBuffer) inbound.Delivery {
	d := inbound.Delivery{Owner: owner, Raw: rawBody(m), Size: m.RFC822Size}
	if m.Envelope != nil {
		d.Subject = m.Envelope.Subject
		d.From = firstAddr(m.Envelope.From)
		d.To = joinAddrs(m.Envelope.To)
		d.Envelope = mapEnvelope(m.Envelope)
	}
	return d
}

// mapEnvelope mirrors an IMAP envelope into the store's IMAP-free Envelope so the
// read face can serve FETCH ENVELOPE / header SEARCH from metadata.
func mapEnvelope(e *imap.Envelope) *inbound.Envelope {
	return &inbound.Envelope{
		Date:      e.Date,
		Subject:   e.Subject,
		From:      mapAddrs(e.From),
		Sender:    mapAddrs(e.Sender),
		ReplyTo:   mapAddrs(e.ReplyTo),
		To:        mapAddrs(e.To),
		Cc:        mapAddrs(e.Cc),
		Bcc:       mapAddrs(e.Bcc),
		InReplyTo: e.InReplyTo,
		MessageID: e.MessageID,
	}
}

func mapAddrs(as []imap.Address) []inbound.Address {
	if len(as) == 0 {
		return nil
	}
	out := make([]inbound.Address, len(as))
	for i, a := range as {
		out[i] = inbound.Address{Name: a.Name, Mailbox: a.Mailbox, Host: a.Host}
	}
	return out
}

func rawBody(m *imapclient.FetchMessageBuffer) []byte {
	if len(m.BodySection) == 0 {
		return nil
	}
	return m.BodySection[0].Bytes
}

func formatAddr(a imap.Address) string {
	addr := a.Mailbox + "@" + a.Host
	if a.Name != "" {
		return a.Name + " <" + addr + ">"
	}
	return addr
}

func firstAddr(as []imap.Address) string {
	if len(as) == 0 {
		return ""
	}
	return formatAddr(as[0])
}

func joinAddrs(as []imap.Address) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, formatAddr(a))
	}
	return strings.Join(parts, ", ")
}
