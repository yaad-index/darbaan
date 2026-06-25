package backend

import (
	"context"
	"errors"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// Sender releases an approved message to the real upstream. It is the only
// component that can cause mail to leave Darbaan, which is why it is a distinct
// seam: until a real Sender is wired (a later issue), default-deny is structural
// — an approved message reaches this seam and goes no further (ADR 0003).
type Sender interface {
	Send(ctx context.Context, msg sluice.Message) error
}

// ErrSendPending is returned by the stub Sender: approval reaches the send seam,
// but no upstream backend exists yet, so nothing is delivered.
var ErrSendPending = errors.New("upstream send pending")

// StubSender is the v1 placeholder Sender. It always returns ErrSendPending, so
// nothing is ever actually sent. The approval still records and audits the
// attempt; the message is never quietly dropped.
type StubSender struct{}

// Send always fails with ErrSendPending.
func (StubSender) Send(context.Context, sluice.Message) error { return ErrSendPending }
