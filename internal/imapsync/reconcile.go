package imapsync

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
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
