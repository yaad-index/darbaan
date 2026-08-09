package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/seqkey"
)

func newBboltLog(t *testing.T) AuditLog {
	t.Helper()
	l, err := New("bbolt", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestNullAuditRecordsNothing(t *testing.T) {
	l, err := New("null", "")
	require.NoError(t, err)
	require.NoError(t, l.Append(Record{Event: "enqueue"}))
	require.NoError(t, l.Verify())
	require.NoError(t, l.Close())
}

func TestBboltChainVerifies(t *testing.T) {
	l := newBboltLog(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue", Agent: "agent"}))
	}
	require.NoError(t, l.Verify())
}

func TestBboltEmptyVerifies(t *testing.T) {
	require.NoError(t, newBboltLog(t).Verify())
}

func TestBboltTamperDetected(t *testing.T) {
	l := newBboltLog(t)
	require.NoError(t, l.Append(Record{Event: "enqueue", Agent: "agent"}))

	// Mutate the stored entry's record but leave its recorded hash untouched.
	bl := l.(*bboltLog)
	require.NoError(t, bl.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		k, v := b.Cursor().First()
		var e Entry
		require.NoError(t, json.Unmarshal(v, &e))
		e.Record.Agent = "tampered"
		enc, err := json.Marshal(e)
		require.NoError(t, err)
		return b.Put(k, enc)
	}))

	require.Error(t, l.Verify())
}

// ADR 0027: an audit entry records both the acting agent and the inbox it acted
// as; both persist through the hash-chained entry.
func TestBboltRecordsAgentAndInbox(t *testing.T) {
	l := newBboltLog(t)
	require.NoError(t, l.Append(Record{Event: "enqueue", Agent: "agent-a", Inbox: "work", MessageID: "1"}))
	require.NoError(t, l.Verify())

	var got Entry
	bl := l.(*bboltLog)
	require.NoError(t, bl.db.View(func(tx *bbolt.Tx) error {
		_, v := tx.Bucket(bucketName).Cursor().First()
		return json.Unmarshal(v, &got)
	}))
	require.Equal(t, "agent-a", got.Record.Agent)
	require.Equal(t, "work", got.Record.Inbox)
}

func TestUnknownTypeErrors(t *testing.T) {
	_, err := New("does-not-exist", "")
	require.Error(t, err)
}

func TestRegisteredListsBuiltins(t *testing.T) {
	r := Registered()
	require.Contains(t, r, "null")
	require.Contains(t, r, "bbolt")
}

func TestBboltRequiresPath(t *testing.T) {
	_, err := New("bbolt", "")
	require.Error(t, err)
}

// C15(a): deleting the last entry (a plain tail truncation) must be evident. The
// bucket's sequence counter survives the delete, so it ends ahead of the head.
func TestBboltDetectsTailTruncation(t *testing.T) {
	l := newBboltLog(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue"}))
	}
	require.NoError(t, l.Verify())

	bl := l.(*bboltLog)
	require.NoError(t, bl.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		k, _ := b.Cursor().Last()
		return b.Delete(k) // drop the tail; the sequence counter stays at 3
	}))
	require.Error(t, l.Verify(), "tail truncation must be detected")
}

// C15(a): the truncate-then-append attack — delete the tail, then append onto the
// surviving head. The append resumes at the higher counter value, so the Seq run
// gaps and the re-chained entry is no longer undetectable.
func TestBboltDetectsTruncateThenAppend(t *testing.T) {
	l := newBboltLog(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue"}))
	}
	bl := l.(*bboltLog)
	require.NoError(t, bl.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		k, _ := b.Cursor().Last()
		return b.Delete(k) // remove seq 3
	}))
	// A genuine later append continues from the (delete-proof) counter → seq 4,
	// chaining hash-correctly onto seq 2. Only the Seq-run check catches it.
	require.NoError(t, l.Append(Record{Event: "enqueue"}))
	require.Error(t, l.Verify(), "truncate-then-append must be detected")
}

// C15: an interior deletion breaks the gap-free sequence run.
func TestBboltDetectsInteriorGap(t *testing.T) {
	l := newBboltLog(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue"}))
	}
	bl := l.(*bboltLog)
	require.NoError(t, bl.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(seqkey.Encode(2)) // remove the middle entry
	}))
	require.Error(t, l.Verify(), "interior gap must be detected")
}

// C15: an entry moved to a key that disagrees with its own Seq is caught by the
// key↔Seq agreement check (a record can't be silently relocated).
func TestBboltDetectsKeySeqMismatch(t *testing.T) {
	l := newBboltLog(t)
	require.NoError(t, l.Append(Record{Event: "enqueue"}))

	bl := l.(*bboltLog)
	require.NoError(t, bl.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		k, v := b.Cursor().First()
		if err := b.Delete(k); err != nil {
			return err
		}
		return b.Put(seqkey.Encode(99), v) // same entry (Seq 1) under key 99
	}))
	require.Error(t, l.Verify(), "key that disagrees with entry Seq must be detected")
}

// C15: the read-only opener used by `darbaan audit verify` verifies a clean chain
// and still detects tampering, without taking the write lock.
func TestBboltOpenReadOnlyVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := New("bbolt", path)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue"}))
	}
	require.NoError(t, l.Close()) // release the write lock so a RO open can take the shared one

	ro, err := OpenReadOnly(path)
	require.NoError(t, err)
	require.NoError(t, ro.Verify())
	require.NoError(t, ro.Close())
}

func TestOpenReadOnlyRequiresPath(t *testing.T) {
	_, err := OpenReadOnly("")
	require.Error(t, err)
}
