package sluice

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
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

	// Scope every assertion to the arrival line itself, not to the whole
	// buffer. Buffer-wide Contains would still pass if the fields drifted onto
	// separate log records — the test would be satisfied while the thing it
	// exists to protect, one line an operator can grep, had broken.
	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "outbound message held") {
			require.Empty(t, line, "expected exactly one arrival line")
			line = l
		}
	}
	require.NotEmpty(t, line, "no arrival line logged")

	require.Contains(t, line, "message_id="+msg.ID)
	require.Contains(t, line, "agent=agent-x")
	require.Contains(t, line, "inbox=inbox-y")
	require.Contains(t, line, "rcpt_count=2")

	// Recipients are counted, never named: the process log is the widest-read
	// surface here and an address is the one field with no operational use.
	require.NotContains(t, buf.String(), "one@example.test")
	require.NotContains(t, buf.String(), "two@example.test")
}
