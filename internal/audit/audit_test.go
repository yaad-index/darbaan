package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
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
