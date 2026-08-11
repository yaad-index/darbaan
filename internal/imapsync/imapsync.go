package imapsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/yaad-index/darbaan/internal/audit"
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
	inbox      string // the named inbox this syncer feeds (ADR 0023); "" = DefaultInbox
	store      inbound.InboundStore
	state      StateStore
	maxAge     time.Duration  // recency cutoff; 0 = no cutoff (ADR 0008)
	labelStore LabelStoreFunc // Gmail X-GM-LABELS writer; nil = plain keywords only (ADR 0020)
	logger     *slog.Logger   // structured logger; defaults to slog.Default(), injectable via SetLogger
	audit      audit.AuditLog // retract audit sink for on-demand stale-mapping drops (#190); nil = no audit
	assess     AssessHook     // injection assessment at ingest (ADR 0032); nil = off
}

// AssessHook, when set, runs the injection assessment on a message's fetched
// content at ingest — during the sync pull, before the message is exposed to the
// agent — and returns the disposition to persist alongside it (ADR 0032
// Amendment 1, eager-at-ingest). It runs once per message on the sync thread, off
// the agent-read path. A nil hook (the default) disables assessment entirely: the
// pull stores headers-only pending records and the body is fetched lazily on read
// (ADR 0019), with no assessment. A nil *inbound.Assessment return likewise means
// "not assessed" → normal flow.
type AssessHook func(inbox, from string, raw []byte, env *inbound.Envelope) *inbound.Assessment

// SetAssessHook installs the injection-assessment hook (ADR 0032). Leaving it
// unset keeps assessment off.
func (s *Syncer) SetAssessHook(h AssessHook) { s.assess = h }

// SetAudit installs the audit sink for on-demand retractions — when a content
// fetch finds the upstream UID gone, the stale mapping is dropped and a "retract"
// record is appended, matching the reconcile loop's audit trail (#190 ask 2). nil
// leaves the drop un-audited (still logged).
func (s *Syncer) SetAudit(a audit.AuditLog) { s.audit = a }

// SetLabelStore installs the Gmail X-GM-LABELS label writer (ADR 0020 20c). When
// set, WriteKeywords replicates label changes via X-GM-LABELS on a Gmail backend
// (capability-gated) and falls back to plain keywords elsewhere.
func (s *Syncer) SetLabelStore(fn LabelStoreFunc) { s.labelStore = fn }

// SetLogger injects the structured logger for this syncer (ADR 0026 #151). serve
// passes a per-inbox logger (logger.With("inbox", name)) so every sync/reconcile
// record is tagged with its inbox; unset falls back to slog.Default().
func (s *Syncer) SetLogger(l *slog.Logger) {
	if l != nil {
		s.logger = l
	}
}

// New builds a Syncer. owner is the agent the synced mail belongs to; inbox is the
// named inbox this syncer feeds (ADR 0023; empty reads as DefaultInbox). maxAge is
// the recency cutoff for the initial/full sync (0 = pull everything).
func New(dial DialFunc, mailbox, owner, inbox string, store inbound.InboundStore, state StateStore, maxAge time.Duration) *Syncer {
	return &Syncer{dial: dial, mailbox: mailbox, owner: owner, inbox: inbox, store: store, state: state, maxAge: maxAge, logger: slog.Default()}
}

// stateKey is the sync-cursor key for this syncer's inbox. The default inbox uses
// the bare upstream mailbox name (the pre-multi-inbox key — its cursor is
// unchanged, no extra re-sync on deploy); a named inbox uses inbox+mailbox so two
// inboxes sharing an upstream mailbox name (e.g. both "INBOX" on different
// accounts) never collide on the cursor (ADR 0023).
func (s *Syncer) stateKey() string {
	if s.inbox == inbound.DefaultInbox {
		return s.mailbox
	}
	return s.inbox + "\x00" + s.mailbox
}

// Watermark returns this account's persisted sync cursor — the mailbox UIDVALIDITY
// and the highest synced UID — for health reporting (#195). It reads the local
// state store only (no upstream contact), so it is cheap to call after each sync
// cycle. Before the first successful sync both are zero.
func (s *Syncer) Watermark() (uidValidity, lastUID uint32, err error) {
	st, err := s.state.Load(s.stateKey())
	if err != nil {
		return 0, 0, err
	}
	return st.UIDValidity, st.LastUID, nil
}

// Dialer is the production DialFunc: TLS-connect to addr and log in with the
// Darbaan-held upstream credentials. The engine is tested with an injected
// DialFunc against an in-process server.
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
	c, err := s.dialContext(ctx)
	if err != nil {
		return 0, err
	}
	// go-imap bounds only the CONNECT phase (its dialer's fixed timeout), not the
	// post-connect commands: a server that accepts the socket and then never answers
	// a SELECT/FETCH would block .Wait() indefinitely. Bind the command phase to ctx
	// by closing the client on cancellation — closing the connection makes any
	// in-flight .Wait() return, a genuine unblock of the blocked call rather than a
	// pre-entry ctx check the hung call never reaches. stop() cancels the hook if
	// Sync returns first (the common, uncancelled path).
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()

	sel, err := c.Select(s.mailbox, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("imapsync: select %q: %w", s.mailbox, err)
	}

	loaded, err := s.state.Load(s.stateKey())
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
		if err := s.state.Save(s.stateKey(), newState); err != nil {
			return stored, err
		}
	}

	// Retry any label writes that failed their immediate upstream replicate
	// (ADR 0020 best-effort write-through). Best-effort; never fails the sync.
	s.reconcileKeywords()

	// Per-cycle visibility (#190 ask 3): one summary line per account per sync, so a
	// stalled or desynced inbox is obvious from the log without reading fetches
	// line-by-line — how many new messages this cycle stored, the local UID
	// watermark (the cursor), and the current UIDVALIDITY.
	s.logger.Info("inbound sync cycle", "stored", stored, "watermark_uid", highest, "uidvalidity", sel.UIDValidity)
	return stored, nil
}

// dialContext runs the injected dial and honors ctx during the CONNECT phase. The
// DialFunc is a blocking network round-trip with no ctx of its own (go-imap bounds
// it only by the dialer's fixed timeout), so a cancellation mid-connect would
// otherwise wait out that whole timeout. dialContext returns promptly on
// cancellation instead; if the dial then completes anyway, its client is closed so
// the connection does not leak. It preserves the "imapsync: connect" error wrap of
// the original inline dial.
func (s *Syncer) dialContext(ctx context.Context) (*imapclient.Client, error) {
	type result struct {
		c   *imapclient.Client
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := s.dial()
		ch <- result{c: c, err: err}
	}()
	select {
	case <-ctx.Done():
		// Drain the in-flight dial so its client (if it lands after cancellation) is
		// closed rather than leaked. This drain goroutine outlives the call until the
		// dial returns; it is bounded by the DialFunc's own connect timeout (go-imap's
		// dialer defaults to ~30s), the weakest of the bounds here but a real one.
		go func() {
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, fmt.Errorf("imapsync: connect: %w", ctx.Err())
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("imapsync: connect: %w", r.err)
		}
		return r.c, nil
	}
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

	// Metadata always: ENVELOPE + RFC822.SIZE (stored so the read face serves FETCH
	// ENVELOPE / RFC822Size / header SEARCH without the body). The body too when
	// assessment is enabled, so the message is assessed and its disposition settled
	// at ingest, before it is ever exposed to the agent (ADR 0032 Amendment 1,
	// eager-at-ingest). With assessment off this stays headers-only and the body is
	// fetched on demand when first read (lazy, ADR 0019).
	opts := &imap.FetchOptions{
		UID:        true,
		Flags:      true, // custom keywords/labels (ADR 0020)
		Envelope:   true,
		RFC822Size: true,
	}
	if s.assess != nil {
		opts.BodySection = []*imap.FetchItemBodySection{{}}
	}
	cmd := c.Fetch(set, opts)

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
		d := deliveryOf(s.owner, s.inbox, m)
		d.UpstreamUID = uid
		d.UIDValidity = uidValidity
		// Eager assessment (ADR 0032 Amendment 1): with a hook installed, assess the
		// fetched body and store the message present + decided in one atomic write,
		// so no reader ever sees a visible-unassessed record. The screener returns a
		// fail-safe held (not-cleared) disposition when the body can't be assessed —
		// a terminal failure, distinct from a transient fetch error, which aborts the
		// pull below without advancing the cursor so the next sync retries. With no
		// hook, store headers-only pending as before (lazy, ADR 0019). Idempotent on
		// (owner, UIDVALIDITY, UID): a re-fetched message is a no-op.
		var added bool
		if s.assess != nil {
			a := s.assess(s.inbox, d.From, d.Raw, d.Envelope)
			added, _, err = s.store.AddSyncedAssessed(d, a)
		} else {
			added, _, err = s.store.AddSyncedPending(d)
		}
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
func (s *Syncer) FetchContent(owner, inbox, id string) (inbound.Message, error) {
	m, err := s.store.Get(owner, inbox, id)
	if err != nil {
		return inbound.Message{}, err
	}
	if !m.Pending {
		// Already present — no upstream contact. Still gate the body: a held-and-
		// unapproved record (stored present by the transition fallback below, or by
		// eager ingest) must never yield its real body on the read path, even on a
		// REPEAT fetch — the IMAP snapshot may predate the hold decision, so this is
		// the authoritative withhold, not just the triggering fetch. The operator
		// surface reads the stored body via store.Get and is unaffected.
		return withheldIfHeld(m), nil
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
		// The mailbox was reset upstream: the whole UID space changed, so this
		// mapping is stale. Don't drop a single record here — a UIDVALIDITY change is
		// the reconcile loop's re-seed concern, not a per-message expunge. Surface it
		// and let the read face serve empty rather than hang (#190).
		s.logger.Warn("content unavailable: mailbox reset",
			"id", id, "have_uidvalidity", m.UIDValidity, "upstream_uidvalidity", sel.UIDValidity)
		return inbound.Message{}, fmt.Errorf("imapsync: content for %s unavailable: mailbox reset (uidvalidity %d != %d): %w", id, sel.UIDValidity, m.UIDValidity, inbound.ErrContentUnavailable)
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
		// The upstream UID is gone (expunged) while its local mapping survives — the
		// exact stale mapping that hangs a client's fetch (#190). Drop it now so it
		// can't poison future fetches, instead of waiting for the hourly reconcile
		// pass; this mirrors the reconcile retraction (ADR 0026) at the moment of
		// detection. Best-effort: even if the drop fails, return the sentinel so the
		// read face serves empty and the client proceeds.
		s.logger.Warn("content unavailable: upstream uid gone, dropping stale mapping",
			"id", id, "upstream_uid", m.UpstreamUID)
		if derr := s.store.RemoveSynced(owner, inbox, id); derr != nil {
			s.logger.Error("could not drop stale mapping", "id", id, "upstream_uid", m.UpstreamUID, "err", derr)
		} else if s.audit != nil {
			// Best-effort audit, consistent with the reconcile retraction record; a
			// failed append must not fail the already-committed drop (ADR 0011).
			_ = s.audit.Append(audit.Record{
				Event:     "retract",
				Agent:     owner,
				Inbox:     inbound.NormInbox(inbox),
				MessageID: id,
				Detail:    fmt.Sprintf("inbox=%s upstream_uid=%d content fetch found upstream uid gone", inbound.NormInbox(inbox), m.UpstreamUID),
			})
		}
		return inbound.Message{}, fmt.Errorf("imapsync: content for %s unavailable: upstream uid %d not found: %w", id, m.UpstreamUID, inbound.ErrContentUnavailable)
	}
	// Steady state: with assessment ON a message is assessed and stored present at
	// ingest (pull, ADR 0032 Amendment 1), so it is never pending here. The
	// exception is the flag-flip TRANSITION backlog — records synced while
	// assessment was OFF are still pending when the flag is later enabled, and a
	// naive SetContent would store their bodies un-assessed, a visible-unassessed
	// leak the Amendment forbids. So when a hook is installed, assess this pre-flip
	// record's freshly-fetched body here as a fallback and store it present +
	// decided, exactly as the ingest path would have. If that assessment HOLDS the
	// message, do not surface its body on THIS in-flight read — the next SELECT
	// re-reads the now-decided disposition and hides (undecided) or tombstones
	// (rejected) it; clearing Raw keeps the triggering FETCH from serving a body the
	// operator has not exposed. With no hook (assessment off) this is the plain lazy
	// path, byte-identical to before (ADR 0019).
	if s.assess == nil {
		return s.store.SetContent(owner, inbox, id, raw)
	}
	a := s.assess(s.inbox, m.From, raw, m.Envelope)
	full, err := s.store.SetContentAssessed(owner, inbox, id, raw, a)
	if err != nil {
		return inbound.Message{}, err
	}
	if full.HeldByAssessment() && full.HoldDecision != inbound.HoldApproved {
		s.logger.Warn("assessed a pre-flip backlog record on read; holding for the operator",
			"id", id, "inbox", inbound.NormInbox(inbox))
	}
	return withheldIfHeld(full), nil
}

// withheldIfHeld blanks a message's body when the injection assessment holds it
// and the operator has not approved exposure, so the lazy content path never
// yields an un-exposed held body on ANY fetch — including a repeat fetch of a
// record already stored present (ADR 0032 Amendment 1). The real body stays in the
// store for the operator hold surface (read via store.Get); a later SELECT re-reads
// the decided state and hides (undecided) or tombstones (rejected) it.
func withheldIfHeld(m inbound.Message) inbound.Message {
	if m.HeldByAssessment() && m.HoldDecision != inbound.HoldApproved {
		m.Raw = nil
	}
	return m
}

// WriteKeywords replicates a message's keyword set to the upstream backend over a
// SEPARATE read-write session — the narrow label-write exception to read-only
// upstream (ADR 0020). It converges the upstream message to want by FETCHing its
// current keywords and applying the +/- delta, so it is idempotent and handles
// both additions and removals (content + delete stay read-only). The local store
// is canonical; a failure here is returned so the caller logs + reconciles later.
func (s *Syncer) WriteKeywords(owner, inbox, id string, add, remove []string) error {
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	m, err := s.store.Get(owner, inbox, id)
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
	dirty, err := s.store.DirtyKeywords(s.owner, s.inbox)
	if err != nil {
		s.logger.Warn("keyword reconcile: list dirty failed", "err", err)
		return
	}
	for _, m := range dirty {
		// Additive re-apply: reconcile has the wanted set, not a delta, so a
		// failed immediate label REMOVE is NOT reconciled (the label lingers
		// upstream). Deliberate — acceptable for the add-dominated labeling flow;
		// the deferred convergent read-side / go-imap upstream swap cleans it up.
		if err := s.WriteKeywords(s.owner, s.inbox, m.ID, m.Keywords, nil); err != nil {
			s.logger.Warn("keyword reconcile deferred", "id", m.ID, "err", err)
			continue
		}
		if err := s.store.ClearKeywordsDirty(s.owner, s.inbox, m.ID); err != nil {
			s.logger.Warn("keyword reconcile: clear dirty failed", "id", m.ID, "err", err)
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

func deliveryOf(owner, inbox string, m *imapclient.FetchMessageBuffer) inbound.Delivery {
	d := inbound.Delivery{Owner: owner, Inbox: inbox, Raw: rawBody(m), Size: m.RFC822Size, Keywords: keywordsOf(m.Flags)}
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
