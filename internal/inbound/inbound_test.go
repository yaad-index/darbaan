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
