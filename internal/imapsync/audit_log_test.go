package imapsync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// failingAudit fails every append, to prove a broken audit sink is surfaced
// (logged) rather than silently swallowed, while the retraction itself still
// commits — the audit is best-effort, but never silent.
type failingAudit struct{}

func (failingAudit) Append(audit.Record) error { return errors.New("audit sink down") }
func (failingAudit) Verify() error             { return nil }
func (failingAudit) Close() error              { return nil }

// logHasMsg reports whether any JSON log line in buf carries the given msg.
func logHasMsg(buf *bytes.Buffer, msg string) bool {
	for _, ln := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(ln, &m) == nil && m["msg"] == msg {
			return true
		}
	}
	return false
}

// Reconcile site: a failed retract-audit append is logged, and the retraction is
// still committed. Before the fix the error was discarded (_ = Append(...)), so a
// broken audit sink left a retraction with no trail and no signal.
func TestReconcileRetractAuditFailureIsLogged(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\n1")
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\n2")
	appendMsg(t, user, "From: c@x.test\r\nSubject: three\r\n\r\n3")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)

	expungeUID(t, addr, 2) // UID 2 leaves the source

	var buf bytes.Buffer
	syncer.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	removed, err := syncer.Reconcile(context.Background(), imapsync.ReconcileOptions{Audit: failingAudit{}})
	require.NoError(t, err, "a failed audit append must not fail the retraction")
	assert.Equal(t, 1, removed, "the gone message is still retracted despite the audit failure")
	assert.True(t, logHasMsg(&buf, "could not audit retraction"),
		"a failed retract-audit append is logged, not silently discarded")
}

// On-demand site: FetchContent finding the upstream UID gone drops the stale
// mapping and audits it; a failed audit append is logged, and the drop still
// commits. The mirror of the reconcile case for the fetch-time retraction path.
func TestFetchContentVanishedMappingAuditFailureIsLogged(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: real\r\n\r\nbody")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)
	syncer.SetAudit(failingAudit{})

	_, err := syncer.Sync(context.Background())
	require.NoError(t, err)
	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	id, upUID := msgs[0].ID, msgs[0].UpstreamUID

	expungeUID(t, addr, upUID) // the message vanishes upstream; the local mapping stays

	var buf bytes.Buffer
	syncer.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	_, ferr := syncer.FetchContent("agent", inbound.DefaultInbox, id)
	assert.ErrorIs(t, ferr, inbound.ErrContentUnavailable)

	// The stale mapping is still dropped despite the audit failure...
	_, gerr := store.Get("agent", inbound.DefaultInbox, id)
	assert.ErrorIs(t, gerr, inbound.ErrNotFound, "the retraction still commits")
	// ...and the audit failure is surfaced, not swallowed.
	assert.True(t, logHasMsg(&buf, "could not audit stale-mapping retraction"),
		"a failed on-demand retract-audit append is logged")
}
