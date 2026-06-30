package imapsync_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// ListUpstreamUIDs returns the mailbox's current UIDVALIDITY and the full set of
// present UIDs — the authoritative present-set reconciliation (ADR 0026) diffs
// against the synced store.
func TestListUpstreamUIDs(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\n1")
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\n2")
	appendMsg(t, user, "From: c@x.test\r\nSubject: three\r\n\r\n3")

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)

	uidValidity, uids, err := syncer.ListUpstreamUIDs()
	require.NoError(t, err)
	assert.NotZero(t, uidValidity, "a selected mailbox always reports a UIDVALIDITY")
	assert.ElementsMatch(t, []uint32{1, 2, 3}, uids, "every appended message's UID is listed")
}

// An empty mailbox lists no UIDs but still reports its UIDVALIDITY — the
// reconcile guard distinguishes "source is empty" (UIDVALIDITY present, no UIDs)
// from "listing failed" (error), and only the latter is skipped.
func TestListUpstreamUIDsEmpty(t *testing.T) {
	addr, _ := startUpstream(t)

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)

	uidValidity, uids, err := syncer.ListUpstreamUIDs()
	require.NoError(t, err)
	assert.NotZero(t, uidValidity)
	assert.Empty(t, uids)
}
