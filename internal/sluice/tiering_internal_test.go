package sluice

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/seqkey"
)

func newTieredStore(t *testing.T) *bboltStore {
	t.Helper()
	al, err := audit.New("null", "")
	require.NoError(t, err)
	ms, err := newBbolt(filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ms.Close(); _ = al.Close() })
	return ms.(*bboltStore)
}

// A new message keeps its raw bytes OUT of bbolt (in the blob), and persists
// subject + size so List never needs the blob — the crux of the tiering.
func TestEnqueueTiersContent(t *testing.T) {
	q := newTieredStore(t)
	m, err := q.Enqueue(Submission{Agent: "a", Raw: []byte("Subject: hi there\r\n\r\nthe body")})
	require.NoError(t, err)

	seq, err := strconv.ParseUint(m.ID, 10, 64)
	require.NoError(t, err)
	var rec stored
	require.NoError(t, q.db.View(func(tx *bbolt.Tx) error {
		return json.Unmarshal(tx.Bucket(bucketMessages).Get(seqkey.Encode(seq)), &rec)
	}))
	assert.True(t, rec.Blobbed)
	assert.Nil(t, rec.Raw, "raw must not be stored in bbolt")
	assert.Equal(t, "hi there", rec.Subject) // persisted, not derived at list time
	assert.Equal(t, len(m.Raw), rec.Size)

	got, err := q.Get(m.ID) // reassembles metadata + blob
	require.NoError(t, err)
	assert.Equal(t, m.Raw, got.Raw)
}

// A legacy record (pre-ADR-0018: a bare Message with inline raw, no Blobbed /
// subject / size) is read back from the inline bytes — Get returns the raw and
// List derives subject + size. No migrate-on-open.
func TestLegacyInlineRecordFallback(t *testing.T) {
	q := newTieredStore(t)
	legacy := Message{
		ID: "1", Agent: "a", From: "f", Rcpt: []string{"r"},
		Raw: []byte("Subject: old format\r\n\r\nbody"), Status: StatusPending,
		ReceivedAt: time.Now().UTC(),
	}
	enc, err := json.Marshal(legacy) // old on-disk shape = the Message itself
	require.NoError(t, err)
	require.NoError(t, q.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketMessages).Put(seqkey.Encode(1), enc)
	}))

	got, err := q.Get("1")
	require.NoError(t, err)
	assert.Equal(t, legacy.Raw, got.Raw) // inline raw, no blob read

	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "old format", metas[0].Subject) // derived from inline raw
	assert.Equal(t, len(legacy.Raw), metas[0].Size)

	// A legacy message still transitions, and the verdict reads back its raw.
	approved, err := q.Approve("1", "op", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, approved.Status)
	assert.Equal(t, legacy.Raw, approved.Raw)
}
