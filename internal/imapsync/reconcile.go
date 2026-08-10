package imapsync

import (
	"context"
	"errors"
	"fmt"

	"github.com/emersion/go-imap/v2"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// DefaultReconcileCapFraction is the safety-cap fraction used when an inbox does
// not configure one (ADR 0026): a pass that would retract more than this fraction
// of the inbox's synced set latches instead of purging. Half the set is a
// conservative anomaly threshold; the operator can tune it per inbox.
const DefaultReconcileCapFraction = 0.5

// DefaultReconcileCapFloor is the absolute floor used when an inbox does not
// configure one (ADR 0026): the cap never latches unless at least this many
// messages would be retracted, regardless of the fraction. Without it a pure
// fraction would latch a tiny inbox on a single normal removal (1 of 2 = 50%);
// the floor keeps the cap an anomaly backstop that only bites at scale.
const DefaultReconcileCapFloor = 5

// ErrReconcileHeld is returned by Reconcile when the safety cap has the inbox
// latched (this pass tripped it, or a prior pass did and it has not been
// released). It is an expected hold, not a failure: the caller distinguishes it
// with errors.Is and reports it as held, not as an error.
var ErrReconcileHeld = errors.New("imapsync: reconcile held: cap exceeded, awaiting operator release")

// ErrReconcileNotHeld is returned by ReleaseReconcile when the inbox is not
// latched — there is nothing to release. The guard matters because release runs
// CAP-BYPASSED: releasing a non-held inbox would purge the current gone-set with
// no safety cap, so release refuses unless the cap is actually holding it.
var ErrReconcileNotHeld = errors.New("imapsync: inbox is not held by the safety cap (nothing to release)")

// ListUpstreamUIDs returns the inbox mailbox's current UIDVALIDITY and the full
// set of UIDs present upstream right now. It is the authoritative present-set
// that upstream reconciliation (ADR 0026) diffs against the synced store to find
// messages that have left the source (deleted, archived out, or un-labeled out of
// a label-folder-scoped mailbox).
//
// It is strictly READ-ONLY: EXAMINE (not SELECT) plus UID SEARCH ALL, and writes
// nothing — the upstream is never modified (ADR 0002). It returns an error on any
// failure (connect / examine / search); reconciliation treats that as "skip this
// cycle" and never deletes on a failed or incomplete listing (fail-safe).
//
// The returned UIDs are unsorted (the order the server reports); the caller diffs
// them as a set, so order does not matter.
func (s *Syncer) ListUpstreamUIDs() (uidValidity uint32, uids []uint32, err error) {
	c, err := s.dial()
	if err != nil {
		return 0, nil, fmt.Errorf("imapsync: connect: %w", err)
	}
	defer func() { _ = c.Logout().Wait(); _ = c.Close() }()

	// EXAMINE opens the mailbox read-only — a listing can never set \Seen or
	// otherwise perturb the source.
	sel, err := c.Select(s.mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return 0, nil, fmt.Errorf("imapsync: examine %q: %w", s.mailbox, err)
	}

	// Empty criteria encode to SEARCH ALL: the complete set of UIDs present under
	// sel.UIDValidity.
	data, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		return 0, nil, fmt.Errorf("imapsync: uid search all in %q: %w", s.mailbox, err)
	}
	all := data.AllUIDs()
	out := make([]uint32, len(all))
	for i, u := range all {
		out[i] = uint32(u)
	}
	return sel.UIDValidity, out, nil
}

// ReconcileOptions configures one reconciliation pass (ADR 0026).
type ReconcileOptions struct {
	// Audit receives a "retract" record for each retracted message (the ADR 0007
	// hash chain). nil disables auditing (a no-op); the production wiring always
	// supplies the real log.
	Audit audit.AuditLog
	// CapFraction is the safety-cap fraction (ADR 0026): a pass that would retract
	// more than this fraction of the synced set latches instead of purging. A value
	// outside (0,1] falls back to DefaultReconcileCapFraction.
	CapFraction float64
	// CapFloor is the safety-cap absolute floor: the cap never latches unless at
	// least this many messages would be retracted. A value < 1 falls back to
	// DefaultReconcileCapFloor. The latch rule is the conjunction of both:
	// retract-count >= floor AND retract-count > fraction * synced-set.
	CapFloor int
	// BypassCap skips the safety cap for this pass. It is set by ReleaseReconcile
	// for the operator-ack release of a latched inbox: the operator has confirmed
	// the large removal is legitimate, so the held purge completes without
	// re-latching. Normal (non-release) passes leave it false.
	BypassCap bool
}

// Reconcile runs one upstream-reconciliation pass for this syncer's inbox
// (ADR 0026): it retracts the local copy of every synced message that has LEFT
// the source mailbox (deleted, archived out, or un-labeled out of a label-folder-
// scoped mailbox), while NEVER modifying the upstream itself (ADR 0002). It
// returns the number of messages retracted.
//
// Guards, applied in order:
//
//  1. List the current upstream present-set (read-only, ListUpstreamUIDs). Any
//     failure returns an error and retracts nothing — reconciliation never
//     deletes on a failed or incomplete listing (fail-safe).
//  2. UIDVALIDITY-skip: if the mailbox's current UIDVALIDITY differs from the
//     forward-sync cursor's, the whole UID space changed (a mailbox reset, a full
//     re-sync per ADR 0019) — NOT a signal that every message was deleted. Skip
//     presence-deletion this cycle and let the forward sync own the re-sync.
//  3. Synced-only set-diff: a record is a retraction candidate only if it carries
//     an upstream UID (UpstreamUID != 0 — locally-generated bounces are never
//     reconciled), matches the current UIDVALIDITY (records under a superseded
//     validity are the forward re-sync's concern), and its UID is absent from the
//     upstream present-set.
//  4. Retract each candidate (RemoveSynced) and append a retract audit record.
//     Per-message failures are collected and the pass continues (best-effort), so
//     one stuck record never blocks the rest; the next cycle retries the failures.
//
// Before retracting, a SAFETY CAP holds a too-large purge: if the candidate set
// clears an absolute floor and exceeds a configured fraction of the synced set,
// the pass latches the inbox (suspends reconciliation) and returns
// ErrReconcileHeld instead of purging — the anomaly backstop against a
// source-side mass removal silently emptying the store. A latched inbox stays
// held (every pass returns ErrReconcileHeld) until an operator release.
func (s *Syncer) Reconcile(ctx context.Context, opts ReconcileOptions) (int, error) {
	// Already latched by a prior pass and not yet released: hold without listing or
	// purging (no wasted upstream round-trip).
	rs, err := s.state.LoadReconcile(s.stateKey())
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: load latch: %w", err)
	}
	if rs.Suspended {
		return 0, ErrReconcileHeld
	}

	// Load the sync cursor BEFORE snapshotting the upstream (C7). Sync and reconcile
	// overlap by design (both fire at startup; a STATUS-triggered sync adds more), so
	// a message can arrive upstream and be stored by a concurrent Sync AFTER our
	// present-set snapshot below but BEFORE we list the store. Such a message is
	// absent from the snapshot yet present locally — and retracting it would be
	// silent permanent loss, since the sync cursor has already advanced past its UID
	// and it is never re-pulled. Capturing the cursor here, before the snapshot,
	// bounds retraction to UIDs at or below it; anything above is too fresh to judge
	// against this snapshot and is left for the next pass.
	loaded, err := s.state.Load(s.stateKey())
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: load state: %w", err)
	}
	cursorUID := loaded.LastUID

	// Guard 1: authoritative present-set (read-only). Failure ⇒ skip (fail-safe).
	uidValidity, upUIDs, err := s.ListUpstreamUIDs()
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: %w", err)
	}

	// Guard 2: UIDVALIDITY-skip. A mismatch between the cursor's validity and the
	// upstream's means the UID space changed (mailbox reset) or forward sync has not
	// run yet — the current-validity set-diff below would be meaningless, so skip.
	if loaded.UIDValidity != uidValidity {
		return 0, nil
	}

	present := make(map[uint32]bool, len(upUIDs))
	for _, u := range upUIDs {
		present[u] = true
	}

	msgs, err := s.store.List(s.owner, s.inbox)
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: list store: %w", err)
	}
	// Guard 3: synced-only set-diff. A candidate is a synced record whose UID is no
	// longer present upstream, with two exclusions and one addition:
	//   - a locally-generated record (no upstream UID, e.g. a bounce) is never
	//     retracted;
	//   - C7: a record whose UID is ABOVE the pre-snapshot cursor may have been
	//     stored by a Sync running concurrently with (after) our upstream snapshot,
	//     so it is too fresh to judge — leave it for the next pass rather than risk
	//     retracting a legitimate new message the snapshot merely predates;
	//   - C8: a record under a SUPERSEDED UIDVALIDITY is orphaned — its UID is
	//     meaningless in the current UID space and forward sync only ever adds, never
	//     cleans — so reconcile owns its cleanup and treats it as a candidate,
	//     counted under the same cap/latch as any other retraction.
	var gone []inbound.Message
	syncedCount := 0
	for _, m := range msgs {
		if m.UpstreamUID == 0 {
			continue // locally-generated — never retracted
		}
		if m.UIDValidity != uidValidity {
			syncedCount++ // C8: superseded-validity orphan is a candidate
			gone = append(gone, m)
			continue
		}
		if m.UpstreamUID > cursorUID {
			continue // C7: too fresh to judge against this snapshot
		}
		syncedCount++
		if !present[m.UpstreamUID] {
			gone = append(gone, m)
		}
	}

	// Safety cap (ADR 0026): hold a too-large purge instead of auto-purging. Latch
	// only when the candidate set BOTH clears the absolute floor (so a tiny inbox
	// never false-latches on a normal single removal) AND exceeds the configured
	// fraction of the synced set. A latch suspends the inbox until an operator
	// release; the upstream is untouched (nothing is purged this pass).
	frac := opts.CapFraction
	if frac <= 0 || frac > 1 {
		frac = DefaultReconcileCapFraction
	}
	floor := opts.CapFloor
	if floor < 1 {
		floor = DefaultReconcileCapFloor
	}
	if !opts.BypassCap && len(gone) >= floor && float64(len(gone)) > frac*float64(syncedCount) {
		if err := s.state.SaveReconcile(s.stateKey(), ReconcileState{Suspended: true, HeldCount: len(gone)}); err != nil {
			return 0, fmt.Errorf("imapsync: reconcile: latch: %w", err)
		}
		// Structured "reconcile held" event — the hook for the #149 latch-push
		// notification. The inbox is carried by the injected per-inbox logger.
		s.logger.Warn("reconcile held", "candidates", len(gone), "synced", syncedCount, "cap_fraction", frac)
		return 0, ErrReconcileHeld
	}

	// Guard 4: retract each candidate + audit, best-effort.
	removed := 0
	var errs []error
	for _, m := range gone {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := s.store.RemoveSynced(s.owner, s.inbox, m.ID); err != nil {
			errs = append(errs, fmt.Errorf("retract %s (uid %d): %w", m.ID, m.UpstreamUID, err))
			continue
		}
		removed++
		if opts.Audit != nil {
			// Best-effort audit (the message store is the source of truth; a failed
			// append must not fail an already-committed retraction — ADR 0011).
			_ = opts.Audit.Append(audit.Record{
				Event:     "retract",
				Agent:     s.owner,
				Inbox:     inbound.NormInbox(s.inbox),
				MessageID: m.ID,
				Detail:    fmt.Sprintf("inbox=%s upstream_uid=%d left source", inbound.NormInbox(s.inbox), m.UpstreamUID),
			})
		}
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("imapsync: reconcile: %d of %d retraction(s) failed: %w", len(errs), len(gone), errors.Join(errs...))
	}
	return removed, nil
}

// ReleaseReconcile is the operator-ack release of a latched inbox (ADR 0026): it
// clears the reconcile latch and runs one pass with the safety cap bypassed, so
// the held retraction completes once. The operator has confirmed the large
// removal is legitimate; after this pass, normal capped operation resumes (a new
// anomaly would latch again). The pass re-lists the upstream, so the purge
// reflects the source's state at release time, not a stale snapshot from when it
// latched.
func (s *Syncer) ReleaseReconcile(ctx context.Context, opts ReconcileOptions) (int, error) {
	// Refuse to release an inbox that is not actually held: release runs the pass
	// cap-bypassed, so releasing a non-held inbox would purge with no safety cap.
	// Only a real latch may be released (ErrReconcileNotHeld otherwise).
	rs, err := s.state.LoadReconcile(s.stateKey())
	if err != nil {
		return 0, fmt.Errorf("imapsync: release: load latch: %w", err)
	}
	if !rs.Suspended {
		return 0, ErrReconcileNotHeld
	}
	// Clear the latch first so the suspended-check in Reconcile lets the pass run;
	// BypassCap then stops it from re-latching on the same large purge.
	if err := s.state.SaveReconcile(s.stateKey(), ReconcileState{}); err != nil {
		return 0, fmt.Errorf("imapsync: release: clear latch: %w", err)
	}
	opts.BypassCap = true
	return s.Reconcile(ctx, opts)
}

// ReconcileLatch reports the inbox's current reconcile latch (ADR 0026) — whether
// reconciliation is suspended and the candidate count that tripped it. The
// operator status surface reads it to show which inboxes are held.
func (s *Syncer) ReconcileLatch() (ReconcileState, error) {
	return s.state.LoadReconcile(s.stateKey())
}
