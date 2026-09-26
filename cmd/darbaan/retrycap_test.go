package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func newRetryCapQueue(t *testing.T, limit int) (*retryCapQueue, *[]string) {
	t.Helper()
	al, err := audit.New("bbolt", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = al.Close() })
	store, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	var rejected []string
	q := &retryCapQueue{MessageStore: store, domain: "darbaan.test", limit: limit,
		reject: func(_ context.Context, id, reason string) error {
			rejected = append(rejected, id)
			_, err := store.Reject(id, "retry-cap", reason, false, "retry-cap")
			return err
		}}
	return q, &rejected
}

func threaded(bounceOf string) sluice.Submission {
	return sluice.Submission{Agent: "agent", From: "agent@x.test", Rcpt: []string{"r@y.test"},
		Raw: []byte("In-Reply-To: <darbaan-bounce." + bounceOf + "@darbaan.test>\r\nSubject: again\r\n\r\nb")}
}

// ADR 0006 (2026-09-26 amendment): resubmissions threaded on a bounce are counted
// against the original; the one past the limit is rejected permanently.
func TestRetryCapRejectsPastTheLimit(t *testing.T) {
	q, rejected := newRetryCapQueue(t, 2)
	orig, err := q.Enqueue(sluice.Submission{Agent: "agent", From: "agent@x.test", Raw: []byte("Subject: s\r\n\r\nb")})
	require.NoError(t, err)

	r1, err := q.Enqueue(threaded(orig.ID))
	require.NoError(t, err)
	r2, err := q.Enqueue(threaded(r1.ID)) // threaded on the resubmission's bounce
	require.NoError(t, err)
	assert.Empty(t, *rejected, "within the limit nothing is rejected")
	assert.Equal(t, sluice.StatusPending, r2.Status)

	r3, err := q.Enqueue(threaded(orig.ID))
	require.NoError(t, err, "the submission itself is accepted; the cap rejects it afterwards")
	assert.Equal(t, []string{r3.ID}, *rejected)
	assert.Equal(t, sluice.StatusRejected, r3.Status, "the returned message is the rejected one")
	assert.False(t, r3.Retryable, "rejected permanently: do not retry")
	assert.Contains(t, r3.Reason, "retry cap reached")
}

// A fresh, unthreaded message is never counted, whatever it contains.
func TestRetryCapIgnoresUnthreadedMessages(t *testing.T) {
	q, rejected := newRetryCapQueue(t, 0)
	for i := 0; i < 3; i++ {
		m, err := q.Enqueue(sluice.Submission{Agent: "agent", From: "agent@x.test", Raw: []byte("Subject: same again\r\n\r\nsame body")})
		require.NoError(t, err)
		assert.Empty(t, m.Lineage)
	}
	assert.Empty(t, *rejected, "even with a limit of 0, unthreaded mail is not a resubmission")
}
