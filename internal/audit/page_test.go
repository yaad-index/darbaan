package audit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// seqs extracts the Seq of each entry, for order/paging assertions.
func seqs(entries []Entry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.Seq
	}
	return out
}

func TestPageWalksInSeqOrderAndResumes(t *testing.T) {
	l := newBboltLog(t)
	for i := 0; i < 5; i++ {
		require.NoError(t, l.Append(Record{Event: "enqueue", Agent: "a", MessageID: "m"}))
	}
	r := l.(Reader)

	// after=0 starts at the first entry; a full page is limit-sized and ascending.
	p1, err := r.Page(0, 2)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2}, seqs(p1))

	// Resume strictly after the last Seq seen — no overlap, no gap.
	p2, err := r.Page(2, 2)
	require.NoError(t, err)
	require.Equal(t, []uint64{3, 4}, seqs(p2))

	// A page shorter than limit is the end of the log.
	p3, err := r.Page(4, 2)
	require.NoError(t, err)
	require.Equal(t, []uint64{5}, seqs(p3))

	// Past the tail: empty, not an error.
	p4, err := r.Page(5, 2)
	require.NoError(t, err)
	require.Empty(t, p4)
}

func TestPageCarriesRecordFields(t *testing.T) {
	l := newBboltLog(t)
	require.NoError(t, l.Append(Record{Event: "enqueue", Agent: "agent-a", Inbox: "work", MessageID: "42"}))

	got, err := l.(Reader).Page(0, 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "enqueue", got[0].Record.Event)
	require.Equal(t, "agent-a", got[0].Record.Agent)
	require.Equal(t, "work", got[0].Record.Inbox)
	require.Equal(t, "42", got[0].Record.MessageID)
	require.NotEmpty(t, got[0].Hash) // a real chained entry, not a zero value
}

func TestPageEmptyLogAndLimitEdges(t *testing.T) {
	l := newBboltLog(t)
	r := l.(Reader)

	// Empty log verifies clean and reads clean.
	empty, err := r.Page(0, 10)
	require.NoError(t, err)
	require.Empty(t, empty)

	require.NoError(t, l.Append(Record{Event: "enqueue"}))
	// A non-positive limit returns nothing (and never opens an unbounded read).
	for _, lim := range []int{0, -1} {
		got, err := r.Page(0, lim)
		require.NoError(t, err)
		require.Empty(t, got)
	}
}

// The read capability is deliberately separate from AuditLog: the bbolt backend
// is a Reader, the null backend is not. That type distinction is what lets a
// caller tell "audit disabled" from "this backend cannot list" (ADR 0033 §4).
func TestReaderCapabilityIsBackendSpecific(t *testing.T) {
	bl := newBboltLog(t)
	_, ok := bl.(Reader)
	require.True(t, ok, "bbolt backend must be a Reader")

	nl, err := New("null", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = nl.Close() })
	_, ok = nl.(Reader)
	require.False(t, ok, "null backend must NOT be a Reader")
}
