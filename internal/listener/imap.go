package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// imapMailbox is the only mailbox the v1 read face exposes.
const imapMailbox = "INBOX"

// errReadOnly is returned for every mutating IMAP operation: the v1 face serves
// Darbaan-generated bounces read-only (ADR 0006), it is not a managed mailbox.
var errReadOnly = errors.New("imap: read-only mailbox (serves Darbaan-generated messages only)")

// IMAPServerConfig configures the IMAP read face.
type IMAPServerConfig struct {
	Addr          string
	TLSConfig     *tls.Config // enables STARTTLS; required unless AllowInsecure
	AllowInsecure bool        // permit AUTH over plaintext — local/testing only
}

// ContentFetch resolves a message's full content (Raw) on demand: for a present
// record from its blob, for a pending record by fetching the body from upstream
// (lazy, ADR 0019). It is called per-FETCH, never at SELECT.
type ContentFetch func(owner, id string) (inbound.Message, error)

// IMAPServer serves the agent's mailbox (the InboundStore) over IMAP as a
// translation adapter (ADR 0016): the store is canonical. SELECT snapshots
// metadata only; a body FETCH resolves content per-message via a ContentFetch.
type IMAPServer struct {
	imap *imapserver.Server
}

// NewIMAPServer wires the IMAP read face. TLS is required unless AllowInsecure
// is set (local/testing), mirroring the SMTP face. fetch resolves message
// content on demand; if nil it defaults to reading straight from the store
// (no upstream — bounce-only / sync-disabled deployments have no pending
// records).
func NewIMAPServer(cfg IMAPServerConfig, cred Credential, store inbound.InboundStore, fetch ContentFetch) (*IMAPServer, error) {
	if cfg.TLSConfig == nil && !cfg.AllowInsecure {
		return nil, errors.New("listener: IMAP TLS required (set TLSConfig, or AllowInsecure for local testing)")
	}
	if fetch == nil {
		fetch = func(owner, id string) (inbound.Message, error) { return store.Get(owner, id) }
	}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &imapSession{cred: cred, store: store, fetch: fetch}, nil, nil
		},
		TLSConfig:    cfg.TLSConfig,
		InsecureAuth: cfg.AllowInsecure,
	})
	return &IMAPServer{imap: srv}, nil
}

// ListenAndServe binds addr and serves until Close is called.
func (s *IMAPServer) ListenAndServe(addr string) error { return s.imap.ListenAndServe(addr) }

// Serve serves on an already-open listener (used by tests).
func (s *IMAPServer) Serve(l net.Listener) error { return s.imap.Serve(l) }

// Close stops the server.
func (s *IMAPServer) Close() error { return s.imap.Close() }

// imapSession is one IMAP connection, hard-scoped after Login to the
// authenticated agent (owner). Every store access is owner-keyed, so a session
// can only ever see the agent's own messages.
type imapSession struct {
	cred     Credential
	store    inbound.InboundStore
	fetch    ContentFetch // resolves message content on demand (per-FETCH)
	owner    string
	authed   bool
	selected []inbound.Message // metadata snapshot taken at Select (no content)
}

func (s *imapSession) Close() error { return nil }

func (s *imapSession) Login(username, password string) error {
	if !constEqual(username, s.cred.Username) || !constEqual(password, s.cred.Password) {
		return imapserver.ErrAuthFailed
	}
	s.owner = username
	s.authed = true
	return nil
}

func (s *imapSession) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	if mailbox != imapMailbox {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	msgs, err := s.store.List(s.owner)
	if err != nil {
		return nil, err
	}
	s.selected = msgs

	firstUnseen, uidNext := uint32(0), uint32(1) // UID 0 is invalid (RFC 3501)
	for i, m := range msgs {
		uid := uint32(uidOf(m))
		if uid >= uidNext {
			uidNext = uid + 1
		}
		if !m.Seen && firstUnseen == 0 {
			firstUnseen = uint32(i) + 1
		}
	}
	return &imap.SelectData{
		Flags:             []imap.Flag{imap.FlagSeen},
		PermanentFlags:    []imap.Flag{imap.FlagSeen},
		NumMessages:       uint32(len(msgs)),
		FirstUnseenSeqNum: firstUnseen,
		UIDNext:           imap.UID(uidNext),
		UIDValidity:       1,
	}, nil
}

func (s *imapSession) Unselect() error {
	s.selected = nil
	return nil
}

func (s *imapSession) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if mailbox != imapMailbox {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	msgs, err := s.store.List(s.owner)
	if err != nil {
		return nil, err
	}
	data := &imap.StatusData{Mailbox: mailbox}
	if options.NumMessages {
		n := uint32(len(msgs))
		data.NumMessages = &n
	}
	if options.NumUnseen {
		var unseen uint32
		for _, m := range msgs {
			if !m.Seen {
				unseen++
			}
		}
		data.NumUnseen = &unseen
	}
	uidNext := uint32(1) // UID 0 is invalid (RFC 3501)
	for _, m := range msgs {
		if u := uint32(uidOf(m)); u >= uidNext {
			uidNext = u + 1
		}
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(uidNext)
	}
	if options.UIDValidity {
		data.UIDValidity = 1
	}
	return data, nil
}

func (s *imapSession) List(w *imapserver.ListWriter, _ string, patterns []string, _ *imap.ListOptions) error {
	if len(patterns) == 0 {
		return nil // LIST "" "" is a delimiter query; nothing to enumerate
	}
	return w.WriteList(&imap.ListData{
		Mailbox: imapMailbox,
		Delim:   '/',
	})
}

func (s *imapSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}

	needRaw := fetchNeedsRaw(options)
	var ferr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if ferr != nil {
			return
		}
		if markSeen && !m.Seen {
			if err := s.store.SetSeen(s.owner, m.ID, true); err != nil {
				ferr = err
				return
			}
			m.Seen = true // also updates s.selected via the pointer
		}
		msg := *m
		if needRaw {
			// Resolve content on demand (blob, or upstream for a pending record).
			// A failure surfaces as an IMAP error, never empty/wrong content.
			full, err := s.fetch(s.owner, m.ID)
			if err != nil {
				ferr = err
				return
			}
			full.Seen = m.Seen // keep the in-session flag state
			msg = full
		}
		ferr = fetchMessage(w.CreateMessage(seqNum), msg, options)
	})
	return ferr
}

// fetchNeedsRaw reports whether any requested item requires the message body;
// flags/UID/internal-date alone do not, so a metadata-only FETCH never triggers
// an on-demand content fetch.
func fetchNeedsRaw(o *imap.FetchOptions) bool {
	return o.RFC822Size || o.Envelope || o.BodyStructure != nil || len(o.BodySection) > 0
}

func (s *imapSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	seen, touchesSeen := seenFromStoreFlags(flags)

	var serr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if serr != nil {
			return
		}
		if touchesSeen && m.Seen != seen {
			if err := s.store.SetSeen(s.owner, m.ID, seen); err != nil {
				serr = err
				return
			}
			m.Seen = seen // also updates s.selected via the pointer
		}
		if flags.Silent {
			return
		}
		rw := w.CreateMessage(seqNum)
		rw.WriteUID(uidOf(*m))
		rw.WriteFlags(flagList(*m))
		if err := rw.Close(); err != nil {
			serr = err
		}
	})
	return serr
}

// forEach calls fn for each selected message matching numSet, computing its
// sequence number (position) and resolving UID vs sequence membership. fn
// receives a pointer into s.selected, so flag updates it makes are reflected in
// later in-session reads (e.g. a FLAGS query after a body fetch).
func (s *imapSession) forEach(numSet imap.NumSet, fn func(seqNum uint32, m *inbound.Message)) {
	for i := range s.selected {
		m := &s.selected[i]
		seqNum := uint32(i) + 1
		var match bool
		switch set := numSet.(type) {
		case imap.SeqSet:
			match = set.Contains(seqNum)
		case imap.UIDSet:
			match = set.Contains(uidOf(*m))
		}
		if match {
			fn(seqNum, m)
		}
	}
}

// The mutating operations are unsupported: the v1 face is a read-only view of
// Darbaan-generated messages.
func (s *imapSession) Create(string, *imap.CreateOptions) error              { return errReadOnly }
func (s *imapSession) Delete(string) error                                   { return errReadOnly }
func (s *imapSession) Rename(string, string, *imap.RenameOptions) error      { return errReadOnly }
func (s *imapSession) Subscribe(string) error                                { return errReadOnly }
func (s *imapSession) Unsubscribe(string) error                              { return errReadOnly }
func (s *imapSession) Expunge(*imapserver.ExpungeWriter, *imap.UIDSet) error { return errReadOnly }
func (s *imapSession) Copy(imap.NumSet, string) (*imap.CopyData, error)      { return nil, errReadOnly }

func (s *imapSession) Append(string, imap.LiteralReader, *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, errReadOnly
}

// Search evaluates the criteria over the selected snapshot and returns the
// matching sequence numbers (SEARCH) or UIDs (UID SEARCH). It handles the
// criteria standard clients send right after SELECT (ALL, \Seen/\Unseen, seq/uid
// sets, internal-date SINCE/BEFORE, size, NOT, OR) plus best-effort substring
// matching for HEADER/BODY/TEXT. (Returning an error here surfaces as a
// NO [SERVERBUG] and breaks real clients — #53.)
func (s *imapSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	needRaw := searchNeedsRaw(criteria)
	var (
		data   imap.SearchData
		seqSet imap.SeqSet
		uidSet imap.UIDSet
	)
	for i := range s.selected {
		m := &s.selected[i]
		seqNum := uint32(i) + 1
		cand := *m
		if needRaw {
			// Content-bearing criteria (size / header / body / text) need the
			// body — resolve it on demand for this candidate.
			full, err := s.fetch(s.owner, m.ID)
			if err != nil {
				return nil, err
			}
			full.Seen = m.Seen
			cand = full
		}
		if !matchSearch(seqNum, &cand, criteria) {
			continue
		}
		uid := uidOf(*m)
		uidSet.AddNum(uid)

		var num uint32
		switch numKind {
		case imapserver.NumKindSeq:
			seqSet.AddNum(seqNum)
			num = seqNum
		case imapserver.NumKindUID:
			num = uint32(uid)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	switch numKind {
	case imapserver.NumKindSeq:
		data.All = seqSet
	case imapserver.NumKindUID:
		data.All = uidSet
	}
	return &data, nil
}

// searchNeedsRaw reports whether any criterion needs the message body (size /
// header / body / text), recursing into NOT/OR — so a metadata-only search
// (seq/uid/flags/date) never triggers an on-demand content fetch.
func searchNeedsRaw(c *imap.SearchCriteria) bool {
	if c.Larger != 0 || c.Smaller != 0 || len(c.Header) > 0 || len(c.Body) > 0 || len(c.Text) > 0 {
		return true
	}
	for i := range c.Not {
		if searchNeedsRaw(&c.Not[i]) {
			return true
		}
	}
	for _, or := range c.Or {
		if searchNeedsRaw(&or[0]) || searchNeedsRaw(&or[1]) {
			return true
		}
	}
	return false
}

func matchSearch(seqNum uint32, m *inbound.Message, c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if !set.Contains(seqNum) {
			return false
		}
	}
	for _, set := range c.UID {
		if !set.Contains(uidOf(*m)) {
			return false
		}
	}
	if !matchDate(m.ReceivedAt, c.Since, c.Before) {
		return false
	}
	for _, f := range c.Flag {
		if !hasFlag(m, f) {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if hasFlag(m, f) {
			return false
		}
	}
	if c.Larger != 0 && int64(len(m.Raw)) <= c.Larger {
		return false
	}
	if c.Smaller != 0 && int64(len(m.Raw)) >= c.Smaller {
		return false
	}
	// Only lower-case the (potentially large) raw message when a content
	// criterion actually needs it — the common SEARCH (ALL / flags / seq) skips
	// this allocation entirely (#56).
	if len(c.Header) > 0 || len(c.Text) > 0 || len(c.Body) > 0 {
		low := bytes.ToLower(m.Raw)
		for _, h := range c.Header {
			if !bytes.Contains(low, bytes.ToLower([]byte(h.Key))) ||
				(h.Value != "" && !bytes.Contains(low, bytes.ToLower([]byte(h.Value)))) {
				return false
			}
		}
		for _, t := range c.Text {
			if !bytes.Contains(low, bytes.ToLower([]byte(t))) {
				return false
			}
		}
		for _, b := range c.Body {
			if !bytes.Contains(low, bytes.ToLower([]byte(b))) {
				return false
			}
		}
	}
	for i := range c.Not {
		if matchSearch(seqNum, m, &c.Not[i]) {
			return false
		}
	}
	for _, or := range c.Or {
		if !matchSearch(seqNum, m, &or[0]) && !matchSearch(seqNum, m, &or[1]) {
			return false
		}
	}
	return true
}

// hasFlag reports whether the message has an IMAP flag. v1 persists only \Seen.
func hasFlag(m *inbound.Message, f imap.Flag) bool {
	return f == imap.FlagSeen && m.Seen
}

// matchDate applies SINCE (date >= since) and BEFORE (date < before) on the
// message's internal date, comparing whole days (RFC 3501).
func matchDate(t, since, before time.Time) bool {
	day := dateOnly(t)
	if !since.IsZero() && day.Before(dateOnly(since)) {
		return false
	}
	if !before.IsZero() && !day.Before(dateOnly(before)) {
		return false
	}
	return true
}

func dateOnly(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// No mailbox changes happen out-of-band, so polling and idling are no-ops.
func (s *imapSession) Poll(*imapserver.UpdateWriter, bool) error { return nil }

func (s *imapSession) Idle(_ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

func fetchMessage(w *imapserver.FetchResponseWriter, m inbound.Message, options *imap.FetchOptions) error {
	w.WriteUID(uidOf(m))
	if options.Flags {
		w.WriteFlags(flagList(m))
	}
	if options.InternalDate {
		w.WriteInternalDate(m.ReceivedAt)
	}
	if options.RFC822Size {
		w.WriteRFC822Size(int64(len(m.Raw)))
	}
	if options.Envelope {
		if h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(m.Raw))); err == nil {
			w.WriteEnvelope(imapserver.ExtractEnvelope(h))
		}
	}
	if options.BodyStructure != nil {
		w.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(m.Raw)))
	}
	for _, bs := range options.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(m.Raw), bs)
		wc := w.WriteBodySection(bs, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return w.Close()
}

func flagList(m inbound.Message) []imap.Flag {
	if m.Seen {
		return []imap.Flag{imap.FlagSeen}
	}
	return []imap.Flag{}
}

func seenFromStoreFlags(sf *imap.StoreFlags) (seen, touches bool) {
	hasSeen := false
	for _, f := range sf.Flags {
		if f == imap.FlagSeen {
			hasSeen = true
		}
	}
	switch sf.Op {
	case imap.StoreFlagsAdd:
		return true, hasSeen
	case imap.StoreFlagsDel:
		return false, hasSeen
	case imap.StoreFlagsSet:
		// SET replaces all flags, so \Seen's presence is the target value.
		return hasSeen, true
	}
	return false, false
}

func uidOf(m inbound.Message) imap.UID {
	n, _ := strconv.ParseUint(m.ID, 10, 32)
	return imap.UID(n)
}
