package inbound_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
)

func newStore(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAddSyncedDedup(t *testing.T) {
	s := newStore(t)
	d := inbound.Delivery{Owner: "agent", Subject: "hi", Raw: []byte("Subject: hi\r\n\r\nx"), UpstreamUID: 5, UIDValidity: 1}

	added, m1, err := s.AddSynced(d)
	require.NoError(t, err)
	assert.True(t, added)

	// Same upstream coordinates → idempotent no-op, returns the existing record.
	added, m2, err := s.AddSynced(d)
	require.NoError(t, err)
	assert.False(t, added)
	assert.Equal(t, m1.ID, m2.ID)
	msgs, _ := s.List("agent")
	assert.Len(t, msgs, 1)

	// A different UID is a new message.
	d.UpstreamUID = 6
	added, _, err = s.AddSynced(d)
	require.NoError(t, err)
	assert.True(t, added)

	// Same UID under a different UIDVALIDITY is also new (UIDs unique per validity).
	d.UpstreamUID, d.UIDValidity = 5, 2
	added, _, err = s.AddSynced(d)
	require.NoError(t, err)
	assert.True(t, added)

	msgs, _ = s.List("agent")
	assert.Len(t, msgs, 3)

	// AddSynced requires upstream coordinates.
	_, _, err = s.AddSynced(inbound.Delivery{Owner: "agent"})
	assert.Error(t, err)
}

// SetKeywords marks a record dirty only when it has an upstream to replicate to;
// a local-only record (no UpstreamUID, e.g. a bounce) gets keywords but stays
// out of reconcile (ADR 0020).
func TestSetKeywordsDirtyOnlyWithUpstream(t *testing.T) {
	s := newStore(t)

	// Local-only record (Add → no UpstreamUID): keywords set, not dirty.
	local, err := s.Add(inbound.Delivery{Owner: "agent", Subject: "bounce"})
	require.NoError(t, err)
	_, err = s.SetKeywords("agent", local.ID, []string{"x"})
	require.NoError(t, err)
	got, err := s.Get("agent", local.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, got.Keywords)
	dirty, err := s.DirtyKeywords("agent")
	require.NoError(t, err)
	assert.Empty(t, dirty)

	// Synced record (has UpstreamUID): keyword change IS dirty.
	_, synced, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 5, UIDValidity: 1})
	require.NoError(t, err)
	_, err = s.SetKeywords("agent", synced.ID, []string{"y"})
	require.NoError(t, err)
	dirty, err = s.DirtyKeywords("agent")
	require.NoError(t, err)
	require.Len(t, dirty, 1)
	assert.Equal(t, synced.ID, dirty[0].ID)
}

func TestPendingThenSetContent(t *testing.T) {
	s := newStore(t)
	added, m, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", Subject: "hi", UpstreamUID: 7, UIDValidity: 1})
	require.NoError(t, err)
	assert.True(t, added)
	assert.True(t, m.Pending)

	// A pending record exposes its metadata but no content yet.
	got, err := s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.True(t, got.Pending)
	assert.Empty(t, got.Raw)
	assert.Equal(t, "hi", got.Subject)
	list, err := s.List("agent")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.True(t, list[0].Pending)
	assert.Empty(t, list[0].Raw)

	// SetContent fills the body and marks it present.
	raw := []byte("Subject: hi\r\n\r\nbody")
	filled, err := s.SetContent("agent", m.ID, raw)
	require.NoError(t, err)
	assert.False(t, filled.Pending)
	assert.Equal(t, raw, filled.Raw)

	got, err = s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, got.Pending)
	assert.Equal(t, raw, got.Raw)
}

func TestAddListGet(t *testing.T) {
	s := newStore(t)
	m, err := s.Add(inbound.Delivery{
		Owner: "agent", From: "MAILER-DAEMON@d", To: "s@local", Subject: "Bounce", Raw: []byte("raw"),
	})
	require.NoError(t, err)
	assert.False(t, m.Seen) // lands unseen

	list, err := s.List("agent")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "Bounce", list[0].Subject)

	got, err := s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("raw"), got.Raw)
}

func TestOwnerIsolation(t *testing.T) {
	s := newStore(t)
	m, err := s.Add(inbound.Delivery{Owner: "alice", Raw: []byte("x")})
	require.NoError(t, err)

	list, err := s.List("bob")
	require.NoError(t, err)
	assert.Empty(t, list)

	_, err = s.Get("bob", m.ID) // must not leak another owner's message
	require.ErrorIs(t, err, inbound.ErrNotFound)
}

func TestGetNotFound(t *testing.T) {
	s := newStore(t)
	_, err := s.Get("agent", "999")
	require.ErrorIs(t, err, inbound.ErrNotFound)
	_, err = s.Get("agent", "not-a-number")
	require.ErrorIs(t, err, inbound.ErrNotFound)
}

func TestUnknownTypeErrors(t *testing.T) {
	_, err := inbound.New("does-not-exist", "x.db")
	require.Error(t, err)
}

func TestSetSeen(t *testing.T) {
	s := newStore(t)
	m, err := s.Add(inbound.Delivery{Owner: "agent", Raw: []byte("x")})
	require.NoError(t, err)
	require.False(t, m.Seen)

	require.NoError(t, s.SetSeen("agent", m.ID, true))
	got, err := s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.True(t, got.Seen)

	require.NoError(t, s.SetSeen("agent", m.ID, false))
	got, err = s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.False(t, got.Seen)

	// owner-scoped + not-found
	require.ErrorIs(t, s.SetSeen("other", m.ID, true), inbound.ErrNotFound)
	require.ErrorIs(t, s.SetSeen("agent", "999", true), inbound.ErrNotFound)
}
