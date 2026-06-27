package inbound

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/seqkey"
)

func newTieredStore(t *testing.T) *bboltStore {
	t.Helper()
	ms, err := newBbolt(filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ms.Close() })
	return ms.(*bboltStore)
}

// Add keeps the raw bytes OUT of bbolt (in the blob); Get and List reassemble
// them — bbolt stays small regardless of mailbox size.
func TestAddTiersContent(t *testing.T) {
	s := newTieredStore(t)
	m, err := s.Add(Delivery{Owner: "agent", Subject: "bounce", Raw: []byte("Subject: bounce\r\n\r\nbody")})
	require.NoError(t, err)

	seq, err := strconv.ParseUint(m.ID, 10, 64)
	require.NoError(t, err)
	var rec stored
	require.NoError(t, s.db.View(func(tx *bbolt.Tx) error {
		return json.Unmarshal(tx.Bucket(bucketInbound).Get(seqkey.Encode(seq)), &rec)
	}))
	assert.True(t, rec.Blobbed)
	assert.Nil(t, rec.Raw, "raw must not be stored in bbolt")
	assert.Equal(t, "bounce", rec.Subject) // subject is already metadata

	got, err := s.Get("agent", m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.Raw, got.Raw) // reassembled from the blob

	// List is metadata-only (no blob reads): content comes per-FETCH via Get.
	list, err := s.List("agent")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "bounce", list[0].Subject)
	assert.Empty(t, list[0].Raw)
}

// sweepOrphans reclaims a blob with no metadata record but keeps a referenced one.
func TestSweepOrphans(t *testing.T) {
	s := newTieredStore(t)
	m, err := s.Add(Delivery{Owner: "agent", Raw: []byte("Subject: x\r\n\r\nbody")})
	require.NoError(t, err)
	require.NoError(t, s.blobs.Put("9999", []byte("orphan"))) // no metadata record

	require.NoError(t, s.sweepOrphans())

	got, err := s.Get("agent", m.ID) // referenced blob survived
	require.NoError(t, err)
	assert.NotEmpty(t, got.Raw)
	_, err = s.blobs.Get("9999") // orphan reclaimed
	assert.Error(t, err)
}

// A legacy record (pre-ADR-0018: a bare inline-raw Message) is read back from
// the inline bytes by Get and List, mutates via SetSeen, and stays owner-scoped.
func TestLegacyInlineFallback(t *testing.T) {
	s := newTieredStore(t)
	legacy := Message{
		ID: "1", Owner: "agent", From: "MAILER-DAEMON", To: "a",
		Subject: "old", Raw: []byte("Subject: old\r\n\r\nbody"), ReceivedAt: time.Now().UTC(),
	}
	enc, err := json.Marshal(legacy) // old on-disk shape = the Message itself
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).Put(seqkey.Encode(1), enc)
	}))

	got, err := s.Get("agent", "1")
	require.NoError(t, err)
	assert.Equal(t, legacy.Raw, got.Raw) // inline raw, no blob read

	// List is metadata-only now (content fetched per-FETCH): metadata present,
	// Raw empty even for a legacy inline record.
	list, err := s.List("agent")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "old", list[0].Subject)
	assert.Empty(t, list[0].Raw)

	// SetSeen mutates metadata and keeps the inline raw readable.
	require.NoError(t, s.SetSeen("agent", "1", true))
	got, err = s.Get("agent", "1")
	require.NoError(t, err)
	assert.True(t, got.Seen)
	assert.Equal(t, legacy.Raw, got.Raw)

	// Owner isolation is preserved.
	_, err = s.Get("other", "1")
	assert.ErrorIs(t, err, ErrNotFound)
}
