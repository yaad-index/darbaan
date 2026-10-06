package main

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/inboxcfg"
	"github.com/yaad-index/darbaan/internal/riskscore"
	"github.com/yaad-index/darbaan/internal/sluice"
	"github.com/yaad-index/darbaan/internal/telemetry/telemetrytest"
)

func newMeteredStore(t *testing.T) (meteredStore, func() map[string]telemetrytest.Instrument) {
	t.Helper()
	al, err := audit.New("bbolt", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })
	m, collect := telemetrytest.New(t)
	return meteredStore{MessageStore: q, metrics: m}, collect
}

func submission() sluice.Submission {
	return sluice.Submission{Agent: "a", From: "a@example.com", Rcpt: []string{"b@example.com"}, Raw: []byte("Subject: x\r\n\r\nbody\r\n")}
}

// Each committed step of the approval chain is counted once; a step the store
// refuses is not, and the pending gauge counts what waits.
func TestTheStoreCountsTheApprovalChain(t *testing.T) {
	s, collect := newMeteredStore(t)
	a, err := s.Enqueue(submission())
	require.NoError(t, err)
	b, err := s.Enqueue(submission())
	require.NoError(t, err)
	_, err = s.Enqueue(submission())
	require.NoError(t, err)
	_, err = s.Approve(a.ID, "op", nil, "", "")
	require.NoError(t, err)
	_, err = s.Reject(b.ID, "op", "no", false, "")
	require.NoError(t, err)
	_, err = s.Approve(a.ID, "op", nil, "", "")
	require.Error(t, err, "approving twice is refused")
	_, err = s.Reject(a.ID, "op", "no", false, "")
	require.Error(t, err, "rejecting an approved message is refused")

	counts := map[string]int64{}
	for _, p := range collect()["darbaan.outbound.messages"].Points {
		counts[p.Attrs["darbaan.outbound.event"]] = p.Value
	}
	assert.Equal(t, map[string]int64{"queued": 3, "approved": 1, "rejected": 1}, counts)

	n, err := pendingCount(s)()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

type fakeSender struct{ err error }

func (f fakeSender) Send(context.Context, sluice.Message) error { return f.err }

// A real send attempt is timed and counted by outcome; the stub sender's
// "pending" is not an attempt and records nothing.
func TestTheSenderRecordsEachAttempt(t *testing.T) {
	m, collect := telemetrytest.New(t)
	senders := meterSenders(map[string]backend.Sender{
		"ok":   fakeSender{},
		"5xx":  fakeSender{err: fmt.Errorf("backend: send: %w", &smtp.SMTPError{Code: 550})},
		"stub": backend.StubSender{},
	}, m)
	ctx := context.Background()
	assert.NoError(t, senders["ok"].Send(ctx, sluice.Message{}))
	assert.Error(t, senders["5xx"].Send(ctx, sluice.Message{}))
	assert.ErrorIs(t, senders["stub"].Send(ctx, sluice.Message{}), backend.ErrSendPending)

	got := collect()
	counts := map[string]int64{}
	for _, p := range got["darbaan.outbound.messages"].Points {
		counts[p.Attrs["darbaan.outbound.event"]+"|"+p.Attrs["error.type"]] = p.Value
	}
	assert.Equal(t, map[string]int64{"sent|": 1, "send_failed|5xx": 1}, counts)
	var attempts int64
	for _, p := range got["darbaan.send.duration"].Points {
		attempts += p.Value
	}
	assert.Equal(t, int64(2), attempts)
}

// With metrics on, the classifier's requests are measured.
func TestTheClassifierIsMeasured(t *testing.T) {
	srv := stubClassifier(t, nil)
	m, collect := telemetrytest.New(t)
	cli := &CLI{Config: classifierConfig(t, "      enabled: true\n      endpoint: "+srv.URL+"\n      timeout: 1s\n"),
		AssessmentEnabled: true, AssessmentTimeout: 3 * time.Second, metrics: m}
	hook, _, err := cli.buildAssessHook(nil, nilResolver, riskscore.DefaultConfig())
	require.NoError(t, err)
	hook(inbound.DefaultInbox, "x@example.com", []byte("Subject: x\r\n\r\nHi"), &inbound.Envelope{})

	points := collect()["http.client.request.duration"].Points
	require.NotEmpty(t, points)
	assert.Equal(t, "127.0.0.1", points[0].Attrs["server.address"])
	assert.Equal(t, "200", points[0].Attrs["http.response.status_code"])
}

// With metrics on, every syncer the CLI builds records its runs.
func TestTheSyncersAreMeasured(t *testing.T) {
	m, collect := telemetrytest.New(t)
	cli := &CLI{InboundSyncDB: filepath.Join(t.TempDir(), "sync.db"), AgentUsername: "agent", metrics: m}
	inboxes := []inboxcfg.Inbox{{Name: "work", Backend: inboxcfg.Backend{IMAPHost: "127.0.0.1:1"}}}
	syncers, stop, err := cli.newSyncers(inboxes, testInbound(t), func(inbox string) string { return inbox }, nil)
	require.NoError(t, err)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = syncers["work"].Sync(ctx)
	require.Error(t, err, "nothing listens on port 1")

	points := collect()["darbaan.sync.runs"].Points
	require.Len(t, points, 1)
	assert.Equal(t, "failed", points[0].Attrs["darbaan.outcome"])
}

func testInbound(t *testing.T) inbound.InboundStore {
	t.Helper()
	s, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
