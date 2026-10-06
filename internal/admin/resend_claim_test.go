package admin_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// stranded returns a service whose default inbox sends through send, and the
// id of an approved message whose first send failed with firstErr.
func stranded(t *testing.T, firstErr error, send func(sluice.Message) error) (*admin.Service, sluice.MessageStore, inbound.InboundStore, string) {
	t.Helper()
	q, _ := seedStore(t)
	inbox := newInbound(t)
	m, err := q.Enqueue(sluice.Submission{
		Agent: "agent", Inbox: inbound.DefaultInbox, From: "a@x.test", Rcpt: []string{"d@y.test"},
		Raw: []byte("From: a@x.test\r\n\r\nb\r\n"),
	})
	require.NoError(t, err)
	svc := admin.NewService(q, inbox, backend.StubSender{}, testSigner(t), strictRouter(), "darbaan.test")
	first := true
	svc.SetSenders(map[string]backend.Sender{inbound.DefaultInbox: senderFunc(func(msg sluice.Message) error {
		if first {
			first = false
			return firstErr
		}
		return send(msg)
	})})
	_, err = svc.ApproveID(context.Background(), m.ID)
	require.NoError(t, err)
	return svc, q, inbox, m.ID
}

func unknownOutcome() error {
	return fmt.Errorf("backend: send: %w: %w", sluice.ErrOutcomeUnknown, net.ErrClosed)
}

// Two re-sends of one message issued together: exactly one delivers, the
// other is refused as already in progress (ADR 0039 section 1).
func TestConcurrentResendsDeliverOnce(t *testing.T) {
	var delivered atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	svc, q, _, id := stranded(t, errors.New("dial tcp: connection refused"), func(sluice.Message) error {
		delivered.Add(1)
		close(entered)
		<-release // hold the first re-send mid-send
		return nil
	})

	var wg sync.WaitGroup
	var firstErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, firstErr = svc.ReSend(context.Background(), id, false)
	}()
	<-entered
	_, err := svc.ReSend(context.Background(), id, false)
	assert.ErrorIs(t, err, admin.ErrResendInProgress)
	close(release)
	wg.Wait()

	require.NoError(t, firstErr)
	assert.Equal(t, int32(1), delivered.Load())
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Equal(t, sluice.StatusSent, got.Status)
	assert.Nil(t, got.ResendClaim, "recording the outcome released the claim")
}

// A send that may have been delivered never bounces the agent: the bounce
// would say it failed. A permanent rejection, the control, still bounces.
func TestAnUnknownOutcomeIsNotBounced(t *testing.T) {
	q, id := seedStore(t)
	inbox := newInbound(t)
	svc := admin.NewService(q, inbox, fakeSender{unknownOutcome()}, testSigner(t), strictRouter(), "darbaan.test")
	out, err := svc.ApproveID(context.Background(), id)
	require.NoError(t, err)
	assert.Contains(t, out.Warn, "outcome unknown")
	msgs, err := inbox.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Empty(t, msgs, "no bounce")
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Equal(t, "outcome unknown: no final reply from the server", got.SendErr)

	q2, id2 := seedStore(t)
	inbox2 := newInbound(t)
	svc2 := admin.NewService(q2, inbox2, fakeSender{&smtp.SMTPError{Code: 550}}, testSigner(t), strictRouter(), "darbaan.test")
	_, err = svc2.ApproveID(context.Background(), id2)
	require.NoError(t, err)
	msgs, err = inbox2.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Len(t, msgs, 1, "the control: a permanent rejection bounces")
}

// A re-send whose own outcome is unknown does not bounce either.
func TestAnUnknownResendOutcomeIsNotBounced(t *testing.T) {
	svc, q, inbox, id := stranded(t, errors.New("dial tcp: connection refused"), func(sluice.Message) error { return unknownOutcome() })
	out, err := svc.ReSend(context.Background(), id, false)
	require.NoError(t, err)
	assert.Contains(t, out.Warn, "outcome unknown")
	msgs, err := inbox.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Empty(t, msgs)
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.True(t, sluice.IsOutcomeUnknown(got.SendErr))
	assert.Nil(t, got.ResendClaim)
}

// Re-sending a message whose outcome is unknown needs the acknowledgement;
// with it, the re-send runs.
func TestAnUnknownOutcomeNeedsAnAcknowledgementToResend(t *testing.T) {
	var delivered atomic.Int32
	svc, q, _, id := stranded(t, unknownOutcome(), func(sluice.Message) error { delivered.Add(1); return nil })

	_, err := svc.ReSend(context.Background(), id, false)
	assert.ErrorIs(t, err, admin.ErrAckRequired)
	assert.Zero(t, delivered.Load())
	got, err := q.Get(id)
	require.NoError(t, err)
	assert.Nil(t, got.ResendClaim, "a refused re-send leaves no claim")

	out, err := svc.ReSend(context.Background(), id, true)
	require.NoError(t, err)
	assert.Equal(t, string(sluice.StatusSent), out.Status)
	assert.Equal(t, int32(1), delivered.Load())
}

// Over the API, an unacknowledged re-send of an unknown outcome and a re-send
// already in progress each come back as their own error, and the
// acknowledgement goes through.
func TestTheAPICarriesTheResendConflicts(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	block := false
	svc, _, _, id := stranded(t, unknownOutcome(), func(sluice.Message) error {
		if block {
			once.Do(func() { close(entered) })
			<-release
		}
		return errors.New("dial tcp: connection refused")
	})
	srv, err := admin.NewServer("127.0.0.1:0", "tok", svc)
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	c := admin.NewClient(l.Addr().String(), "tok")
	ctx := context.Background()

	_, err = c.ReSend(ctx, id, false)
	assert.ErrorIs(t, err, admin.ErrAckRequired)

	block = true
	done := make(chan error, 1)
	go func() { _, err := c.ReSend(ctx, id, true); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("the acknowledged re-send never reached the sender: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the acknowledged re-send never reached the sender")
	}
	_, err = c.ReSend(ctx, id, true)
	assert.ErrorIs(t, err, admin.ErrResendInProgress)
	close(release)
	assert.NoError(t, <-done, "the acknowledged re-send ran (and failed transiently)")
}
