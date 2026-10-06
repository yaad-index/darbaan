package main

import (
	"context"
	"errors"
	"time"

	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/sluice"
	"github.com/yaad-index/darbaan/internal/telemetry"
)

// meteredStore counts the approval chain's events (ADR 0040) as the store
// commits them: a submission queued, approved or rejected. A call that fails
// counts nothing.
type meteredStore struct {
	sluice.MessageStore
	metrics *telemetry.Metrics
}

func (s meteredStore) Enqueue(sub sluice.Submission) (sluice.Message, error) {
	m, err := s.MessageStore.Enqueue(sub)
	if err == nil {
		s.metrics.Outbound(context.Background(), telemetry.Queued)
	}
	return m, err
}

func (s meteredStore) Approve(id, decidedBy string, released []byte, asInbox, actor string) (sluice.Message, error) {
	m, err := s.MessageStore.Approve(id, decidedBy, released, asInbox, actor)
	if err == nil {
		s.metrics.Outbound(context.Background(), telemetry.Approved)
	}
	return m, err
}

func (s meteredStore) Reject(id, decidedBy, reason string, retryable bool, actor string) (sluice.Message, error) {
	m, err := s.MessageStore.Reject(id, decidedBy, reason, retryable, actor)
	if err == nil {
		s.metrics.Outbound(context.Background(), telemetry.Rejected)
	}
	return m, err
}

// meteredSender records each attempt to release a message upstream: its
// duration, and sent or send_failed with the failure's kind. The stub
// sender's "pending" is not an attempt, so it records nothing.
type meteredSender struct {
	backend.Sender
	metrics *telemetry.Metrics
}

func (s meteredSender) Send(ctx context.Context, msg sluice.Message) error {
	start := time.Now()
	err := s.Sender.Send(ctx, msg)
	if !errors.Is(err, backend.ErrSendPending) {
		s.metrics.Send(ctx, time.Since(start), err)
	}
	return err
}

// meterSenders wraps every sender in senders.
func meterSenders(senders map[string]backend.Sender, m *telemetry.Metrics) map[string]backend.Sender {
	out := make(map[string]backend.Sender, len(senders))
	for name, s := range senders {
		out[name] = meteredSender{Sender: s, metrics: m}
	}
	return out
}

// pendingCount counts the outbound messages waiting for a decision.
func pendingCount(q sluice.MessageStore) func() (int64, error) {
	return func() (int64, error) {
		metas, err := q.List()
		if err != nil {
			return 0, err
		}
		var n int64
		for _, m := range metas {
			if m.Status == sluice.StatusPending {
				n++
			}
		}
		return n, nil
	}
}
