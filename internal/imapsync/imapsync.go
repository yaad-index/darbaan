package imapsync

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

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
	dial       DialFunc
	mailbox    string
	owner      string // the agent whose mailbox this is
	store      inbound.InboundStore
	state      StateStore
	maxAge     time.Duration  // recency cutoff; 0 = no cutoff (ADR 0008)
	labelStore LabelStoreFunc // Gmail X-GM-LABELS writer; nil = plain keywords only (ADR 0020)
}

// SetLabelStore installs the Gmail X-GM-LABELS label writer (ADR 0020 20c). When
// set, WriteKeywords replicates label changes via X-GM-LABELS on a Gmail backend
// (capability-gated) and falls back to plain keywords elsewhere.
func (s *Syncer) SetLabelStore(fn LabelStoreFunc) { s.labelStore = fn }

// New builds a Syncer. owner is the agent the synced mail belongs to. maxAge is
// the recency cutoff for the initial/full sync (0 = pull everything).
func New(dial DialFunc, mailbox, owner string, store inbound.InboundStore, state StateStore, maxAge time.Duration) *Syncer {
	return &Syncer{dial: dial, mailbox: mailbox, owner: owner, store: store, state: state, maxAge: maxAge}
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

	// Retry any label writes that failed their immediate upstream replicate
	// (ADR 0020 best-effort write-through). Best-effort; never fails the sync.
	s.reconcileKeywords()
	return stored, nil
}

// pull fetches new messages and stores them, returning the count stored and the
// new cursor.
//
// The set to fetch comes from pullSet: a CONCRETE (last+1):(uidNext-1) range
// normally, or — with a recency cutoff (ADR 0008) — exactly the messages newer
// than the cutoff date AND the cursor. The fetch is STREAMED (one message
// buffered at a time via cmd.Next), so a large mailbox never loads into memory at
// once. On a mid-stream error the cursor is not advanced, so the next run
// re-syncs — at-least-once, no gaps.
func (s *Syncer) pull(c *imapclient.Client, uidValidity, uidNext, last uint32) (int, uint32, error) {
	set, ceiling, skip, err := s.pullSet(c, uidNext, last)
	if err != nil {
		return 0, last, err
	}
	if skip {
		return 0, ceiling, nil // nothing to fetch; advance the cursor to the ceiling
	}

	// Headers-only: ENVELOPE + RFC822.SIZE (stored as metadata so the read face
	// serves FETCH ENVELOPE / RFC822Size / header SEARCH without the body) but no
	// BODY[] — the body is fetched on demand when first read (lazy, ADR 0019).
	cmd := c.Fetch(set, &imap.FetchOptions{
		UID:        true,
		Flags:      true, // custom keywords/labels (ADR 0020)
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
	// On the recency-cutoff path, advance the cursor to the covered ceiling
	// (uidNext-1) so we step past skipped-old mail — including a high-UID /
	// old-INTERNALDATE message SEARCH SINCE excludes — and never re-evaluate it.
	if ceiling > highest {
		highest = ceiling
	}
	return stored, highest, nil
}

// pullSet builds the UID set to fetch plus the cursor ceiling. Normally that is
// the concrete (last+1):(uidNext-1) range (UIDNEXT gives a strict upper bound —
// go-imap's dynamic "*" is mis-encoded against Gmail; fall back to it only when a
// server reports no UIDNEXT). With a recency cutoff it is the exact intersection
// of "newer than the cutoff date" (UID SEARCH SINCE) and "newer than the cursor"
// — an exact set, not a UID floor, so a high-UID/old-date message is excluded.
//
// Note (forward-only, v1): on the cutoff path the cursor advances to uidNext-1
// regardless, so WIDENING the window later (e.g. 1y→2y) does NOT retroactively
// pull the now-in-range older mail — those UIDs are already behind the cursor.
// Widening requires a cursor reset / re-sync.
func (s *Syncer) pullSet(c *imapclient.Client, uidNext, last uint32) (set imap.UIDSet, ceiling uint32, skip bool, err error) {
	ceiling = last
	if s.maxAge > 0 {
		cutoff := time.Now().Add(-s.maxAge)
		res, e := c.UIDSearch(&imap.SearchCriteria{Since: cutoff}, nil).Wait()
		if e != nil {
			return set, last, false, fmt.Errorf("imapsync: search since %s: %w", cutoff.Format("2006-01-02"), e)
		}
		uids := filterAbove(res.AllUIDs(), last)
		if uidNext > 0 {
			ceiling = uidNext - 1 // the whole range is covered; old mail is skipped
		}
		if len(uids) == 0 {
			return set, ceiling, true, nil
		}
		return uidSetOf(uids), ceiling, false, nil
	}
	if uidNext > 0 {
		hi := uidNext - 1 // highest possible existing UID
		if last+1 > hi {
			return set, last, true, nil // no new messages
		}
		set.AddRange(imap.UID(last+1), imap.UID(hi))
		return set, hi, false, nil
	}
	set.AddRange(imap.UID(last+1), 0) // fallback: dynamic "*"
	return set, last, false, nil
}

// filterAbove returns the UIDs strictly greater than last.
func filterAbove(uids []imap.UID, last uint32) []imap.UID {
	out := uids[:0:0]
	for _, u := range uids {
		if uint32(u) > last {
			out = append(out, u)
		}
	}
	return out
}

// uidSetOf builds a UID set from a list, coalescing consecutive UIDs into ranges
// so the FETCH command stays compact even for a large recent window.
func uidSetOf(uids []imap.UID) imap.UIDSet {
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	var set imap.UIDSet
	for i := 0; i < len(uids); {
		j := i
		for j+1 < len(uids) && uids[j+1] == uids[j]+1 {
			j++
		}
		set.AddRange(uids[i], uids[j])
		i = j + 1
	}
	return set
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

// WriteKeywords replicates a message's keyword set to the upstream backend over a
// SEPARATE read-write session — the narrow label-write exception to read-only
// upstream (ADR 0020). It converges the upstream message to want by FETCHing its
// current keywords and applying the +/- delta, so it is idempotent and handles
// both additions and removals (content + delete stay read-only). The local store
// is canonical; a failure here is returned so the caller logs + reconciles later.
func (s *Syncer) WriteKeywords(owner, id string, add, remove []string) error {
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	m, err := s.store.Get(owner, id)
	if err != nil {
		return err
	}
	if m.UpstreamUID == 0 {
		return fmt.Errorf("imapsync: keyword write for %s: no upstream uid", id)
	}

	// Gmail: replicate as real labels via X-GM-LABELS (capability-gated, ADR 0020
	// 20c). On any other backend the writer reports ErrNotXGM and we fall through
	// to plain keywords.
	if s.labelStore != nil {
		if err := s.labelStore(m.UpstreamUID, m.UIDValidity, add, remove); !errors.Is(err, ErrNotXGM) {
			return err // success, or a real Gmail error
		}
	}

	// Plain IMAP keywords (RFC 3501) — the universal path.
	c, err := s.dial()
	if err != nil {
		return fmt.Errorf("imapsync: connect: %w", err)
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()

	sel, err := c.Select(s.mailbox, nil).Wait() // read-write session
	if err != nil {
		return fmt.Errorf("imapsync: select %q: %w", s.mailbox, err)
	}
	if sel.UIDValidity != m.UIDValidity {
		return fmt.Errorf("imapsync: keyword write for %s: mailbox reset (uidvalidity %d != %d)", id, sel.UIDValidity, m.UIDValidity)
	}
	var set imap.UIDSet
	set.AddNum(imap.UID(m.UpstreamUID))
	if len(add) > 0 {
		if err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: toFlags(add)}, nil).Close(); err != nil {
			return fmt.Errorf("imapsync: keyword add: %w", err)
		}
	}
	if len(remove) > 0 {
		if err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsDel, Silent: true, Flags: toFlags(remove)}, nil).Close(); err != nil {
			return fmt.Errorf("imapsync: keyword remove: %w", err)
		}
	}
	return nil
}

// reconcileKeywords re-replicates locally-dirty keyword sets to upstream — a label
// write whose immediate upstream replicate failed is retried here on the next sync
// (ADR 0020). Best-effort: failures are logged, never fatal to the sync.
func (s *Syncer) reconcileKeywords() {
	dirty, err := s.store.DirtyKeywords(s.owner)
	if err != nil {
		log.Printf("darbaan: keyword reconcile list: %v", err)
		return
	}
	for _, m := range dirty {
		// Additive re-apply (reconcile has the wanted set, not a delta).
		if err := s.WriteKeywords(s.owner, m.ID, m.Keywords, nil); err != nil {
			log.Printf("darbaan: keyword reconcile %s deferred: %v", m.ID, err)
			continue
		}
		if err := s.store.ClearKeywordsDirty(s.owner, m.ID); err != nil {
			log.Printf("darbaan: keyword reconcile clear %s: %v", m.ID, err)
		}
	}
}

func toFlags(kw []string) []imap.Flag {
	f := make([]imap.Flag, len(kw))
	for i, k := range kw {
		f[i] = imap.Flag(k)
	}
	return f
}

func deliveryOf(owner string, m *imapclient.FetchMessageBuffer) inbound.Delivery {
	d := inbound.Delivery{Owner: owner, Raw: rawBody(m), Size: m.RFC822Size, Keywords: keywordsOf(m.Flags)}
	if m.Envelope != nil {
		d.Subject = m.Envelope.Subject
		d.From = firstAddr(m.Envelope.From)
		d.To = joinAddrs(m.Envelope.To)
		d.Envelope = mapEnvelope(m.Envelope)
	}
	return d
}

// keywordsOf returns the custom keywords from a message's flags — the atoms that
// are not backslash-prefixed system flags (\Seen, \Flagged, …). \Seen is tracked
// separately as the Seen field, so it (and the other system flags) are dropped.
func keywordsOf(flags []imap.Flag) []string {
	var kw []string
	for _, f := range flags {
		if !strings.HasPrefix(string(f), "\\") {
			kw = append(kw, string(f))
		}
	}
	return kw
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
