package imapsync

import (
	"context"
	"fmt"
	"sort"
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

// Sync runs one incremental pull: SELECT the mailbox, UID-FETCH everything newer
// than the stored cursor, store each via inbound.Add (tiered), and advance the
// cursor. A UIDVALIDITY change resets the cursor and re-syncs from scratch. The
// upstream is read-only (no flag/delete write-back, v1). Returns the count
// stored this run.
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

	// UID FETCH (last+1):* — a fresh mailbox (last 0) fetches 1:* (everything).
	var set imap.UIDSet
	set.AddRange(imap.UID(last+1), 0) // Stop 0 == "*"
	msgs, err := c.Fetch(set, &imap.FetchOptions{
		UID:         true,
		Envelope:    true,
		BodySection: []*imap.FetchItemBodySection{{}}, // whole message
	}).Collect()
	if err != nil {
		return 0, fmt.Errorf("imapsync: fetch: %w", err)
	}

	// Ascending UID so the cursor advances monotonically.
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].UID < msgs[j].UID })

	highest := last
	stored := 0
	for _, m := range msgs {
		uid := uint32(m.UID)
		// "N:*" returns the highest existing message even when N is past it;
		// skip anything not actually newer than the cursor.
		if uid <= last {
			continue
		}
		if _, err := s.store.Add(deliveryOf(s.owner, m)); err != nil {
			return stored, fmt.Errorf("imapsync: store uid %d: %w", uid, err)
		}
		stored++
		if uid > highest {
			highest = uid
		}
	}

	newState := State{UIDValidity: sel.UIDValidity, LastUID: highest}
	if newState != loaded {
		if err := s.state.Save(s.mailbox, newState); err != nil {
			return stored, err
		}
	}
	return stored, nil
}

func deliveryOf(owner string, m *imapclient.FetchMessageBuffer) inbound.Delivery {
	d := inbound.Delivery{Owner: owner, Raw: rawBody(m)}
	if m.Envelope != nil {
		d.Subject = m.Envelope.Subject
		d.From = firstAddr(m.Envelope.From)
		d.To = joinAddrs(m.Envelope.To)
	}
	return d
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
