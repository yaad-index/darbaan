package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/yaad-index/darbaan/internal/bounceguard"
	"github.com/yaad-index/darbaan/internal/filter"
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
type ContentFetch func(owner, inbox, id string) (inbound.Message, error)

// KeywordWriter replicates a keyword change to the upstream backend as an
// add/remove delta (the label write-through, ADR 0020). The local store is
// canonical; a returned error means the upstream replicate failed and is
// reconciled later. nil disables write-through (local-only labels — e.g. sync
// disabled).
type KeywordWriter func(owner, inbox, id string, add, remove []string) error

// SyncTrigger runs a debounced on-demand upstream pull of an inbox (ADR 0028),
// invoked when a client issues STATUS for an inbox the operator opted in. It is
// best-effort: a returned error is logged, never surfaced to the client (STATUS
// still reports the store's current counts). nil disables on-demand sync (the
// back-compat / no-opted-in-inbox path), and it is a no-op for an inbox that is
// not opted in or whose debounce window has not elapsed.
type SyncTrigger func(inbox string) error

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
// filters maps each inbox name to its compiled serve-time filter (ADR 0021/0022).
// The keys are the configured inboxes (ADR 0023); each is exposed as an IMAP
// mailbox (the default inbox as INBOX). A single-inbox deploy passes one entry
// keyed DefaultInbox.
// mailOwner returns an inbox's synced-mail store owner (ADR 0027): the inbox name
// in multi-agent mode, so agents sharing an inbox read the same records. nil (the
// single-agent / back-compat path) keys synced mail by the connecting agent, as
// before.
// syncNow triggers a debounced on-demand upstream pull of an inbox on STATUS
// (ADR 0028); nil disables on-demand sync (STATUS stays a plain query).
func NewIMAPServer(cfg IMAPServerConfig, auth *Auth, store inbound.InboundStore, fetch ContentFetch, writeKeywords KeywordWriter, filters map[string]*filter.Filter, guard *bounceguard.Guard, holdSpoof bool, mailOwner func(inbox string) string, syncNow SyncTrigger) (*IMAPServer, error) {
	if cfg.TLSConfig == nil && !cfg.AllowInsecure {
		return nil, errors.New("listener: IMAP TLS required (set TLSConfig, or AllowInsecure for local testing)")
	}
	if len(filters) == 0 {
		filters = map[string]*filter.Filter{inbound.DefaultInbox: nil} // no filter = allow-all default inbox
	}
	if fetch == nil {
		fetch = func(owner, inbox, id string) (inbound.Message, error) { return store.Get(owner, inbox, id) }
	}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &imapSession{auth: auth, store: store, fetch: fetch, writeKeywords: writeKeywords, filters: filters, guard: guard, holdSpoof: holdSpoof, mailOwner: mailOwner, syncNow: syncNow}, nil, nil
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
// authenticated agent (ADR 0027). The read face is grant-gated (only inboxes the
// agent may read) and, per selected inbox, unions the inbox's shared synced mail
// (keyed by the inbox mail-owner) with the agent's own private bounces (keyed by
// the agent), so a co-reader never sees another agent's bounce.
type imapSession struct {
	auth          *Auth
	store         inbound.InboundStore
	fetch         ContentFetch              // resolves message content on demand (per-FETCH)
	writeKeywords KeywordWriter             // replicates a keyword change upstream (nil = local-only)
	filters       map[string]*filter.Filter // per-inbox serve-time filter (ADR 0021/0022/0023)
	guard         *bounceguard.Guard        // inbound bounce-spoof guard, ahead of the filter (nil = off; ADR 0024)
	holdSpoof     bool                      // on_spoof=hold-for-human → held-semantics; false = hide
	principal     *Principal                // the authenticated agent + its grants (ADR 0027)
	mailOwner     func(inbox string) string // synced-mail owner key per inbox (ADR 0027); nil = key by the connecting agent
	syncNow       SyncTrigger               // debounced on-demand pull on STATUS (ADR 0028); nil = disabled
	owner         string
	selectedInbox string // the inbox name of the SELECTed mailbox (ADR 0023)
	authed        bool
	selected      []inbound.Message // metadata snapshot taken at Select (no content)
}

// defaultInbox is the inbox this session sees as IMAP INBOX: the connecting
// agent's configured default_inbox (ADR 0027), or the global default inbox for an
// unrestricted single-agent session (back-compat).
func (s *imapSession) defaultInbox() string {
	if s.principal != nil && s.principal.DefaultInbox != "" {
		return s.principal.DefaultInbox
	}
	return inbound.DefaultInbox
}

// canRead reports whether the connecting agent may read the inbox (ADR 0027). An
// unrestricted principal (single-agent / back-compat) may read every inbox.
func (s *imapSession) canRead(inbox string) bool {
	return s.principal.CanRead(inbox)
}

// mailboxName maps an inbox name to its IMAP mailbox name for THIS session: the
// connecting agent's default_inbox is exposed as INBOX, every other inbox by its
// own name (per-principal naming, ADR 0027; the single global default at N=1).
func (s *imapSession) mailboxName(inbox string) string {
	if inbox == s.defaultInbox() {
		return imapMailbox
	}
	return inbox
}

// resolveMailbox maps an IMAP mailbox name back to a configured inbox name the
// connecting agent may read, reporting whether it exists. An inbox the agent
// lacks read on is reported as non-existent — absence is indistinguishable from
// non-existence (privacy by omission, ADR 0027).
func (s *imapSession) resolveMailbox(mailbox string) (string, bool) {
	for inbox := range s.filters {
		if !s.canRead(inbox) {
			continue
		}
		if s.mailboxName(inbox) == mailbox {
			return inbox, true
		}
	}
	return "", false
}

// mailboxNames returns the IMAP mailbox names the connecting agent may read,
// sorted for stable LIST (ADR 0027 read-scoping).
func (s *imapSession) mailboxNames() []string {
	names := make([]string, 0, len(s.filters))
	for inbox := range s.filters {
		if !s.canRead(inbox) {
			continue
		}
		names = append(names, s.mailboxName(inbox))
	}
	sort.Strings(names)
	return names
}

// syncedOwner is the store owner key for an inbox's synced upstream mail
// (ADR 0027): the inbox's mail-owner in multi-agent mode, or the connecting agent
// when unset (single-agent / back-compat), where it coincides with s.owner.
func (s *imapSession) syncedOwner(inbox string) string {
	if s.mailOwner != nil {
		return s.mailOwner(inbox)
	}
	return s.owner
}

// listAndFilter returns the inbox's full message list and the filtered-visible
// subset (ADR 0021). The full list is kept so UIDNEXT can be derived from the
// highest UID overall — deriving it from the visible subset would under-report
// when the highest-UID messages are hidden, breaking client sync. allow is
// visible; hide and undecided/rejected hold are omitted. Evaluated fresh each
// call (no cache).
//
// The inbox's mail is the union of two owner key-spaces (ADR 0027): its synced
// upstream mail (owned by the inbox's mail-owner, shared by every reader) and the
// connecting agent's OWN bounces (owned by the agent, private to it). When the
// two owners coincide (single-agent / back-compat) one List already holds both.
func (s *imapSession) listAndFilter(inbox string) (full, visible []inbound.Message, err error) {
	syncedOwner := s.syncedOwner(inbox)
	full, err = s.store.List(syncedOwner, inbox)
	if err != nil {
		return nil, nil, err
	}
	if s.owner != syncedOwner {
		bounces, berr := s.store.List(s.owner, inbox)
		if berr != nil {
			return nil, nil, berr
		}
		full = append(full, bounces...)
		// Keep UIDs strictly ascending across the merged set (store ids are globally
		// increasing), so the mailbox view stays well-ordered for the client.
		sort.Slice(full, func(i, j int) bool { return uidOf(full[i]) < uidOf(full[j]) })
	}
	flt := s.filters[inbox] // per-inbox filter (ADR 0023); nil = allow-all
	now := time.Now()
	for _, m := range full { // new backing slice — leave full intact for UIDNEXT
		// The bounce-spoof guard runs AHEAD of the user filter (ADR 0024): it is a
		// security floor, so a spoof can't be surfaced by a permissive default or a
		// broad allow rule.
		if s.guard != nil {
			if s.guardHides(m, inbox) {
				continue
			}
		}
		if flt == nil {
			visible = append(visible, m)
			continue
		}
		switch flt.Decide(m, now) {
		case filter.Allow:
			visible = append(visible, m)
		case filter.Hold:
			// Held messages are hidden until a human approves exposure (ADR 0021);
			// rejected/undecided stay hidden (fail-safe).
			if m.HoldDecision == inbound.HoldApproved {
				visible = append(visible, m)
			}
		}
	}
	return full, visible, nil
}

// guardHides reports whether the bounce-spoof guard omits m from the read face.
// A spoof under on_spoof=hide is always omitted; under on_spoof=hold-for-human it
// is omitted until an operator exposes it (held-semantics, like a filter Hold),
// and surfaced for decision via the admin held-list. A non-spoof returns false
// (the user filter then applies). A guard error is fail-CLOSED (Verdict returns
// spoof=true for a bounce-shaped candidate it couldn't fetch/verify, ADR 0024);
// it is logged and the message is hidden.
func (s *imapSession) guardHides(m inbound.Message, inbox string) bool {
	spoof, err := s.guard.Verdict(envelopeFromLocals(m), m.Raw, func() ([]byte, error) {
		fm, e := s.fetch(m.Owner, inbox, m.ID)
		return fm.Raw, e
	})
	if err != nil {
		slog.Warn("imap bounce-guard check failed", "id", m.ID, "err", err)
	}
	if !spoof {
		return false
	}
	if s.holdSpoof && m.HoldDecision == inbound.HoldApproved {
		return false // operator exposed it
	}
	return true
}

// envelopeFromLocals returns the local-parts of a message's envelope From
// addresses (the metadata-cheap input to the guard's From-precheck, ADR 0024).
func envelopeFromLocals(m inbound.Message) []string {
	if m.Envelope == nil {
		return nil
	}
	out := make([]string, 0, len(m.Envelope.From))
	for _, a := range m.Envelope.From {
		out = append(out, a.Mailbox)
	}
	return out
}

// uidNext returns the next UID, derived from the highest UID across ALL stored
// messages (not the filtered view), so a client never sees a too-low UIDNEXT.
func uidNext(full []inbound.Message) imap.UID {
	next := uint32(1) // UID 0 is invalid (RFC 3501)
	for _, m := range full {
		if u := uint32(uidOf(m)); u >= next {
			next = u + 1
		}
	}
	return imap.UID(next)
}

func (s *imapSession) Close() error { return nil }

func (s *imapSession) Login(username, password string) error {
	p, ok := s.auth.Verify(username, password)
	if !ok {
		return imapserver.ErrAuthFailed
	}
	s.principal = p
	s.owner = p.Name
	s.authed = true
	return nil
}

func (s *imapSession) Select(mailbox string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	inbox, ok := s.resolveMailbox(mailbox)
	if !ok {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	s.selectedInbox = inbox
	full, visible, err := s.listAndFilter(inbox)
	if err != nil {
		return nil, err
	}
	s.selected = visible

	firstUnseen := uint32(0)
	seen := map[imap.Flag]bool{}
	keywords := []imap.Flag{}
	for i, m := range visible {
		if !m.Seen && firstUnseen == 0 {
			firstUnseen = uint32(i) + 1
		}
		for _, k := range m.Keywords { // advertise the keywords in use (ADR 0020)
			if f := imap.Flag(k); !seen[f] {
				seen[f] = true
				keywords = append(keywords, f)
			}
		}
	}
	// \* in PERMANENTFLAGS signals the client may create new keywords via STORE
	// (ADR 0020 write-through).
	permanent := append([]imap.Flag{imap.FlagSeen}, keywords...)
	permanent = append(permanent, imap.FlagWildcard)
	return &imap.SelectData{
		Flags:             append([]imap.Flag{imap.FlagSeen}, keywords...),
		PermanentFlags:    permanent,
		NumMessages:       uint32(len(visible)),
		FirstUnseenSeqNum: firstUnseen,
		UIDNext:           uidNext(full), // from the full store, not the visible view
		UIDValidity:       1,
	}, nil
}

func (s *imapSession) Unselect() error {
	s.selected = nil
	return nil
}

func (s *imapSession) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	inbox, ok := s.resolveMailbox(mailbox)
	if !ok {
		return nil, fmt.Errorf("imap: no such mailbox %q", mailbox)
	}
	// On-demand sync (ADR 0028): STATUS is the agent's "sync now" — trigger a
	// debounced upstream pull for this inbox BEFORE computing the counts, so the
	// reply reflects mail that arrived since the last background poll. Best-effort:
	// a pull error is logged, never surfaced (STATUS still reports the store's
	// current counts); the trigger is a no-op for an inbox that is not opted in or
	// whose debounce window has not elapsed (silent-skip).
	if s.syncNow != nil {
		if err := s.syncNow(inbox); err != nil {
			slog.Warn("imap on-demand sync failed", "inbox", inbox, "err", err)
		}
	}
	full, visible, err := s.listAndFilter(inbox) // a query, not a selection — selectedInbox unchanged
	if err != nil {
		return nil, err
	}
	data := &imap.StatusData{Mailbox: mailbox}
	if options.NumMessages {
		n := uint32(len(visible))
		data.NumMessages = &n
	}
	if options.NumUnseen {
		var unseen uint32
		for _, m := range visible {
			if !m.Seen {
				unseen++
			}
		}
		data.NumUnseen = &unseen
	}
	if options.UIDNext {
		data.UIDNext = uidNext(full) // from the full store, not the visible view
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
	// Advertise every configured inbox as a mailbox (the default inbox as INBOX),
	// in stable order (ADR 0023).
	for _, name := range s.mailboxNames() {
		if err := w.WriteList(&imap.ListData{Mailbox: name, Delim: '/'}); err != nil {
			return err
		}
	}
	return nil
}

func (s *imapSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}

	var ferr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if ferr != nil {
			return
		}
		if markSeen && !m.Seen {
			if err := s.store.SetSeen(m.Owner, s.selectedInbox, m.ID, true); err != nil {
				ferr = err
				return
			}
			m.Seen = true // also updates s.selected via the pointer
		}
		// fetchMessage resolves content lazily: ENVELOPE / RFC822Size / header
		// fields serve from stored metadata when present, and only a body request
		// (or a record with no stored metadata) triggers getRaw. A resolve failure
		// surfaces as an IMAP error, never empty/wrong content.
		ferr = fetchMessage(w.CreateMessage(seqNum), *m, options, s.rawResolver(*m))
	})
	return ferr
}

// rawFunc lazily resolves a message's raw content.
type rawFunc func() ([]byte, error)

// rawResolver returns a memoized resolver for a message's raw content: it calls
// the content fetcher at most once, and only when a field actually needs the body
// (BodyStructure/BodySection, or ENVELOPE/size/header on a record with no stored
// metadata). Present records resolve from a local blob; a pending record fetches
// upstream once, then is cached present.
func (s *imapSession) rawResolver(m inbound.Message) rawFunc {
	var (
		raw  []byte
		err  error
		done bool
	)
	return func() ([]byte, error) {
		if !done {
			done = true
			var full inbound.Message
			switch full, err = s.fetch(m.Owner, s.selectedInbox, m.ID); {
			case err == nil:
				raw = full.Raw
			case errors.Is(err, inbound.ErrContentUnavailable):
				// The upstream content can't be resolved (a stale local→upstream UID
				// mapping, #190). Serve an empty body rather than erroring: the FETCH
				// response stays well-formed and the command completes, so one
				// unresolvable UID can't stall the client's whole poll. The event is
				// surfaced by the syncer at WARN and the stale mapping is dropped there;
				// the message's stored ENVELOPE / SIZE / FLAGS still serve normally.
				raw, err = nil, nil
			}
		}
		return raw, err
	}
}

func (s *imapSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	seen, touchesSeen := seenFromStoreFlags(flags)

	kw := keywordFlags(flags.Flags) // custom keywords in the STORE request (ADR 0020)

	var serr error
	s.forEach(numSet, func(seqNum uint32, m *inbound.Message) {
		if serr != nil {
			return
		}
		if touchesSeen && m.Seen != seen {
			if err := s.store.SetSeen(m.Owner, s.selectedInbox, m.ID, seen); err != nil {
				serr = err
				return
			}
			m.Seen = seen // also updates s.selected via the pointer
		}
		// Keyword change: a SET always recomputes (it can clear keywords); ADD/DEL
		// only when keyword atoms are present.
		if flags.Op == imap.StoreFlagsSet || len(kw) > 0 {
			next, added, removed := applyKeywordOp(m.Keywords, flags.Op, kw)
			if len(added) > 0 || len(removed) > 0 {
				if _, err := s.store.SetKeywords(m.Owner, s.selectedInbox, m.ID, next); err != nil {
					serr = err
					return
				}
				m.Keywords = next // local store is canonical; update the snapshot
				// Best-effort upstream replicate; a failure leaves the record dirty
				// for the sync to reconcile, never an error to the agent (ADR 0020).
				// Skip records with no upstream (locally-generated, e.g. bounces) —
				// their labels are local-only, nothing to replicate.
				if s.writeKeywords != nil && m.UpstreamUID != 0 {
					if err := s.writeKeywords(m.Owner, s.selectedInbox, m.ID, added, removed); err != nil {
						slog.Warn("imap keyword write-through deferred", "id", m.ID, "err", err)
					} else {
						_ = s.store.ClearKeywordsDirty(m.Owner, s.selectedInbox, m.ID)
					}
				}
			}
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

// keywordFlags returns the custom keyword atoms from a STORE's flags (dropping
// backslash-prefixed system flags like \Seen, handled separately).
func keywordFlags(flags []imap.Flag) []string {
	var kw []string
	for _, f := range flags {
		if !strings.HasPrefix(string(f), "\\") {
			kw = append(kw, string(f))
		}
	}
	return kw
}

// applyKeywordOp applies an IMAP STORE op to a keyword set, returning the new set
// plus the keywords added and removed (for the upstream delta). SET replaces the
// whole set; ADD/DEL adjust it.
func applyKeywordOp(current []string, op imap.StoreFlagsOp, kw []string) (next, added, removed []string) {
	set := map[string]bool{}
	for _, k := range current {
		set[k] = true
	}
	switch op {
	case imap.StoreFlagsAdd:
		for _, k := range kw {
			if !set[k] {
				set[k] = true
				added = append(added, k)
			}
		}
	case imap.StoreFlagsDel:
		for _, k := range kw {
			if set[k] {
				delete(set, k)
				removed = append(removed, k)
			}
		}
	case imap.StoreFlagsSet:
		want := map[string]bool{}
		for _, k := range kw {
			want[k] = true
		}
		for _, k := range kw {
			if !set[k] {
				added = append(added, k)
			}
		}
		for k := range set {
			if !want[k] {
				removed = append(removed, k)
			}
		}
		set = want
	}
	for k := range set {
		next = append(next, k)
	}
	sort.Strings(next)
	sort.Strings(added)
	sort.Strings(removed)
	return next, added, removed
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
	var (
		data   imap.SearchData
		seqSet imap.SeqSet
		uidSet imap.UIDSet
	)
	for i := range s.selected {
		m := &s.selected[i]
		seqNum := uint32(i) + 1
		// matchSearch resolves content lazily and only for content-bearing
		// criteria on records without stored metadata. If a candidate's content
		// can't be resolved, skip it (degrade, don't [SERVERBUG] the whole SEARCH)
		// — but log it: a skipped candidate is a silently-missing result.
		ok, err := matchSearch(seqNum, m, criteria, s.rawResolver(*m))
		if err != nil {
			slog.Warn("imap search skipped message", "id", m.ID, "err", err)
			continue
		}
		if !ok {
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

// matchSearch reports whether a message matches the criteria. Metadata criteria
// (seq/uid/flags/date) and stored-metadata criteria (size, and Subject/From/To/
// Date/... headers when the envelope is stored) match without the body; only
// BODY/TEXT and headers on records with no stored envelope call getRaw. An error
// means the content couldn't be resolved (caller skips + logs the candidate).
func matchSearch(seqNum uint32, m *inbound.Message, c *imap.SearchCriteria, getRaw rawFunc) (bool, error) {
	for _, set := range c.SeqNum {
		if !set.Contains(seqNum) {
			return false, nil
		}
	}
	for _, set := range c.UID {
		if !set.Contains(uidOf(*m)) {
			return false, nil
		}
	}
	if !matchDate(m.ReceivedAt, c.Since, c.Before) {
		return false, nil
	}
	for _, f := range c.Flag {
		if !hasFlag(m, f) {
			return false, nil
		}
	}
	for _, f := range c.NotFlag {
		if hasFlag(m, f) {
			return false, nil
		}
	}
	if c.Larger != 0 || c.Smaller != 0 {
		size, err := sizeOf(m, getRaw)
		if err != nil {
			return false, err
		}
		if c.Larger != 0 && size <= c.Larger {
			return false, nil
		}
		if c.Smaller != 0 && size >= c.Smaller {
			return false, nil
		}
	}
	for _, h := range c.Header {
		ok, err := matchHeader(m, h, getRaw)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	if len(c.Text) > 0 || len(c.Body) > 0 {
		raw, err := getRaw()
		if err != nil {
			return false, err
		}
		low := bytes.ToLower(raw)
		for _, t := range c.Text {
			if !bytes.Contains(low, bytes.ToLower([]byte(t))) {
				return false, nil
			}
		}
		for _, b := range c.Body {
			if !bytes.Contains(low, bytes.ToLower([]byte(b))) {
				return false, nil
			}
		}
	}
	for i := range c.Not {
		ok, err := matchSearch(seqNum, m, &c.Not[i], getRaw)
		if err != nil {
			return false, err
		}
		if ok {
			return false, nil
		}
	}
	for _, or := range c.Or {
		a, err := matchSearch(seqNum, m, &or[0], getRaw)
		if err != nil {
			return false, err
		}
		b := false
		if !a {
			if b, err = matchSearch(seqNum, m, &or[1], getRaw); err != nil {
				return false, err
			}
		}
		if !a && !b {
			return false, nil
		}
	}
	return true, nil
}

// sizeOf returns the message size from stored metadata, falling back to the raw
// length for records synced before the size was stored.
func sizeOf(m *inbound.Message, getRaw rawFunc) (int64, error) {
	if m.Size > 0 {
		return m.Size, nil
	}
	raw, err := getRaw()
	if err != nil {
		return 0, err
	}
	return int64(len(raw)), nil
}

// matchHeader matches one SEARCH HEADER criterion. Stored-envelope headers
// (Subject/From/To/Cc/Bcc/Sender/Reply-To/Date/Message-Id/In-Reply-To) match
// against the stored envelope (no body fetch); any other header — or a record
// with no stored envelope — falls back to a substring match over the raw.
func matchHeader(m *inbound.Message, h imap.SearchCriteriaHeaderField, getRaw rawFunc) (bool, error) {
	if m.Envelope != nil {
		if v, ok := envelopeHeader(m.Envelope, h.Key); ok {
			if h.Value == "" {
				return v != "", nil // header-present check
			}
			return strings.Contains(strings.ToLower(v), strings.ToLower(h.Value)), nil
		}
	}
	raw, err := getRaw()
	if err != nil {
		return false, err
	}
	low := bytes.ToLower(raw)
	if !bytes.Contains(low, bytes.ToLower([]byte(h.Key))) {
		return false, nil
	}
	return h.Value == "" || bytes.Contains(low, bytes.ToLower([]byte(h.Value))), nil
}

// envelopeHeader renders a stored-envelope field for substring matching, or
// ok=false for a header not carried by the envelope (match via raw instead).
func envelopeHeader(e *inbound.Envelope, key string) (string, bool) {
	switch strings.ToLower(key) {
	case "subject":
		return e.Subject, true
	case "from":
		return formatAddrs(e.From), true
	case "sender":
		return formatAddrs(e.Sender), true
	case "reply-to":
		return formatAddrs(e.ReplyTo), true
	case "to":
		return formatAddrs(e.To), true
	case "cc":
		return formatAddrs(e.Cc), true
	case "bcc":
		return formatAddrs(e.Bcc), true
	case "message-id":
		return e.MessageID, true
	case "in-reply-to":
		return strings.Join(e.InReplyTo, " "), true
	case "date":
		if e.Date.IsZero() {
			return "", true
		}
		return e.Date.Format(time.RFC1123Z), true
	}
	return "", false
}

func formatAddrs(as []inbound.Address) string {
	if len(as) == 0 {
		return ""
	}
	parts := make([]string, 0, len(as))
	for _, a := range as {
		addr := a.Mailbox + "@" + a.Host
		if a.Name != "" {
			addr = a.Name + " <" + addr + ">"
		}
		parts = append(parts, addr)
	}
	return strings.Join(parts, ", ")
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

func fetchMessage(w *imapserver.FetchResponseWriter, m inbound.Message, options *imap.FetchOptions, getRaw rawFunc) error {
	w.WriteUID(uidOf(m))
	if options.Flags {
		w.WriteFlags(flagList(m))
	}
	if options.InternalDate {
		w.WriteInternalDate(m.ReceivedAt)
	}
	if options.RFC822Size {
		size, err := sizeOf(&m, getRaw)
		if err != nil {
			return err
		}
		w.WriteRFC822Size(size)
	}
	if options.Envelope {
		env, err := envelopeFor(m, getRaw)
		if err != nil {
			return err
		}
		if env != nil {
			w.WriteEnvelope(env)
		}
	}
	if options.BodyStructure != nil {
		raw, err := getRaw()
		if err != nil {
			return err
		}
		w.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
	}
	for _, bs := range options.BodySection {
		raw, err := getRaw()
		if err != nil {
			return err
		}
		buf := imapserver.ExtractBodySection(bytes.NewReader(raw), bs)
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

// envelopeFor returns the IMAP envelope from stored metadata when present, else
// parses it from the (lazily-resolved) raw — for records synced before the
// envelope was stored, and for locally-generated messages.
func envelopeFor(m inbound.Message, getRaw rawFunc) (*imap.Envelope, error) {
	if m.Envelope != nil {
		return toIMAPEnvelope(m.Envelope), nil
	}
	raw, err := getRaw()
	if err != nil {
		return nil, err
	}
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, nil // unparseable header: omit the envelope (prior behavior)
	}
	return imapserver.ExtractEnvelope(h), nil
}

func toIMAPEnvelope(e *inbound.Envelope) *imap.Envelope {
	return &imap.Envelope{
		Date:      e.Date,
		Subject:   e.Subject,
		From:      toIMAPAddrs(e.From),
		Sender:    toIMAPAddrs(e.Sender),
		ReplyTo:   toIMAPAddrs(e.ReplyTo),
		To:        toIMAPAddrs(e.To),
		Cc:        toIMAPAddrs(e.Cc),
		Bcc:       toIMAPAddrs(e.Bcc),
		InReplyTo: e.InReplyTo,
		MessageID: e.MessageID,
	}
}

func toIMAPAddrs(as []inbound.Address) []imap.Address {
	if len(as) == 0 {
		return nil
	}
	out := make([]imap.Address, len(as))
	for i, a := range as {
		out[i] = imap.Address{Name: a.Name, Mailbox: a.Mailbox, Host: a.Host}
	}
	return out
}

func flagList(m inbound.Message) []imap.Flag {
	flags := make([]imap.Flag, 0, len(m.Keywords)+1)
	if m.Seen {
		flags = append(flags, imap.FlagSeen)
	}
	for _, k := range m.Keywords { // custom keywords/labels (ADR 0020)
		flags = append(flags, imap.Flag(k))
	}
	return flags
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
