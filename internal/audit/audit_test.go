package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func openDB(t *testing.T) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "audit.db"), 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(EnsureBucket))
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestChainVerifies(t *testing.T) {
	db := openDB(t)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		for i := 0; i < 3; i++ {
			if _, err := Append(tx, Record{Event: "enqueue", Agent: "agent"}); err != nil {
				return err
			}
		}
		return nil
	}))
	require.NoError(t, db.View(Verify))
}

func TestEmptyLogVerifies(t *testing.T) {
	db := openDB(t)
	require.NoError(t, db.View(Verify))
}

func TestTamperDetected(t *testing.T) {
	db := openDB(t)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		_, err := Append(tx, Record{Event: "enqueue", Agent: "agent"})
		return err
	}))

	// Mutate the stored entry's record but leave its recorded hash untouched.
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		k, v := b.Cursor().First()
		var e Entry
		require.NoError(t, json.Unmarshal(v, &e))
		e.Record.Agent = "tampered"
		enc, err := json.Marshal(e)
		require.NoError(t, err)
		return b.Put(k, enc)
	}))

	require.Error(t, db.View(Verify))
}
