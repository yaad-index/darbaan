package sluice

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
)

// An arrival must reach the process log, not only the audit log.
//
// Before this, every decision transition logged while Enqueue logged nothing,
// so the log showed decisions on messages it had never seen arrive. Reading it
// during an incident, the messages looked as though they had appeared from
// nowhere — an absence that reads as "nothing happened" when it actually means
// "this path does not log".
//
// The audit record alone did not close that gap: the audit log has no read
// interface, so the one place an operator can look is the process log.
func TestEnqueueLogsArrival(t *testing.T) {
	al, err := audit.New("null", "")
	require.NoError(t, err)
	ms, err := newBbolt(filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ms.Close(); _ = al.Close() })

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(old)

	msg, err := ms.Enqueue(Submission{
		Agent: "agent-x",
		Inbox: "inbox-y",
		Rcpt:  []string{"one@example.test", "two@example.test"},
		Raw:   []byte("raw"),
	})
	require.NoError(t, err)

	got := buf.String()
	require.Contains(t, got, "outbound message held")
	require.Contains(t, got, "message_id="+msg.ID)
	require.Contains(t, got, "agent=agent-x")
	require.Contains(t, got, "inbox=inbox-y")
	require.Contains(t, got, "rcpt_count=2")

	// Recipients are counted, never named: the process log is the widest-read
	// surface here and an address is the one field with no operational use.
	require.NotContains(t, got, "one@example.test")
	require.NotContains(t, got, "two@example.test")
}
