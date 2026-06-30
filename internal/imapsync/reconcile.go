package imapsync

import (
	"context"
	"errors"
	"fmt"

	"github.com/emersion/go-imap/v2"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/inbound"
)

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
// The safety cap that holds a too-large purge (ADR 0026) is layered on top of
// this pass in a following increment — its insertion point is just before the
// retraction loop.
func (s *Syncer) Reconcile(ctx context.Context, opts ReconcileOptions) (int, error) {
	// Guard 1: authoritative present-set (read-only). Failure ⇒ skip (fail-safe).
	uidValidity, upUIDs, err := s.ListUpstreamUIDs()
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: %w", err)
	}

	loaded, err := s.state.Load(s.stateKey())
	if err != nil {
		return 0, fmt.Errorf("imapsync: reconcile: load state: %w", err)
	}
	// Guard 2: UIDVALIDITY-skip. A mismatch (mailbox reset, or no forward sync yet)
	// means the UID space changed, not that everything was deleted.
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
	// Guard 3: synced-only set-diff. Skip locally-generated records (no upstream
	// UID) and records under a superseded UIDVALIDITY; a candidate is a synced
	// record whose UID is no longer present upstream.
	var gone []inbound.Message
	for _, m := range msgs {
		if m.UpstreamUID == 0 || m.UIDValidity != uidValidity {
			continue
		}
		if !present[m.UpstreamUID] {
			gone = append(gone, m)
		}
	}

	// (safety-cap insertion point — a following increment holds the pass here when
	// |gone| exceeds a configured fraction of the synced set.)

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
