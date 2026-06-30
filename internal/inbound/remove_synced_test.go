package inbound_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// RemoveSynced hard-removes a synced message: it vanishes from the read face, and
// its dedup-index entry is cleared so the same upstream (UIDVALIDITY, UID) can
// re-sync cleanly if it returns to the source (ADR 0026 re-appearance).
func TestRemoveSyncedHardRemoves(t *testing.T) {
	s := newStore(t)

	_, m, err := s.AddSynced(inbound.Delivery{
		Owner: "agent", Inbox: "work", UpstreamUID: 5, UIDValidity: 1,
		Raw: []byte("From: a@x\r\n\r\nbody"),
	})
	require.NoError(t, err)

	require.NoError(t, s.RemoveSynced("agent", "work", m.ID))

	_, err = s.Get("agent", "work", m.ID)
	assert.ErrorIs(t, err, inbound.ErrNotFound, "removed message is gone from the read face")

	list, err := s.List("agent", "work")
	require.NoError(t, err)
	assert.Empty(t, list, "removed message is gone from the listing")

	// Re-add the same (UIDVALIDITY, UID): added=true proves the dedup index entry
	// was cleared (a stale entry would suppress the re-add as a false duplicate).
	added, _, err := s.AddSynced(inbound.Delivery{
		Owner: "agent", Inbox: "work", UpstreamUID: 5, UIDValidity: 1,
		Raw: []byte("From: a@x\r\n\r\nback"),
	})
	require.NoError(t, err)
	assert.True(t, added, "after retraction the same upstream UID re-syncs as new")
}

// A pending (headers-only, ADR 0019) synced record has no content blob; removing
// it must still succeed (no blob to delete) and clear the record.
func TestRemoveSyncedPending(t *testing.T) {
	s := newStore(t)

	_, m, err := s.AddSyncedPending(inbound.Delivery{
		Owner: "agent", Inbox: "work", UpstreamUID: 9, UIDValidity: 1,
	})
	require.NoError(t, err)

	require.NoError(t, s.RemoveSynced("agent", "work", m.ID))

	_, err = s.Get("agent", "work", m.ID)
	assert.ErrorIs(t, err, inbound.ErrNotFound)
}

// RemoveSynced refuses a locally-generated record (no upstream UID, e.g. a signed
// bounce): those are never subject to reconciliation (ADR 0026). The error is NOT
// ErrNotFound (the record exists), and the record stays readable.
func TestRemoveSyncedRefusesLocallyGenerated(t *testing.T) {
	s := newStore(t)

	m, err := s.Add(inbound.Delivery{
		Owner: "agent", Inbox: "work", From: "MAILER-DAEMON@x", To: "agent@x",
		Subject: "bounce", Raw: []byte("From: MAILER-DAEMON@x\r\n\r\nbounce"),
	})
	require.NoError(t, err)

	err = s.RemoveSynced("agent", "work", m.ID)
	require.Error(t, err)
	assert.False(t, errors.Is(err, inbound.ErrNotFound), "refusal is a guard, not a not-found")

	got, err := s.Get("agent", "work", m.ID)
	require.NoError(t, err, "the locally-generated record is untouched")
	assert.Equal(t, m.ID, got.ID)
}

// RemoveSynced is (owner, inbox)-scoped: a wrong owner or inbox is ErrNotFound and
// leaves the record intact (no cross-tenant retraction).
func TestRemoveSyncedScoping(t *testing.T) {
	s := newStore(t)

	_, m, err := s.AddSynced(inbound.Delivery{
		Owner: "agent", Inbox: "work", UpstreamUID: 3, UIDValidity: 1,
		Raw: []byte("From: a@x\r\n\r\nb"),
	})
	require.NoError(t, err)

	assert.ErrorIs(t, s.RemoveSynced("other", "work", m.ID), inbound.ErrNotFound)
	assert.ErrorIs(t, s.RemoveSynced("agent", "personal", m.ID), inbound.ErrNotFound)
	assert.ErrorIs(t, s.RemoveSynced("agent", "work", "404"), inbound.ErrNotFound)

	_, err = s.Get("agent", "work", m.ID)
	require.NoError(t, err, "a mis-scoped or unknown remove leaves the record intact")
}
