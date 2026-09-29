package backend

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// stallingServer accepts connections and then goes silent. With greet set it
// first sends the 220 greeting and reads one command, so the client is stalled
// part-way through the transaction rather than before it starts. Held
// connections are released when the test ends.
func stallingServer(t *testing.T, greet bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if greet {
					_, _ = conn.Write([]byte("220 test ESMTP\r\n"))
					_, _ = bufio.NewReader(conn).ReadString('\n') // EHLO, never answered
				}
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

func testSender(addr string, timeout time.Duration) *smtpSender {
	return &smtpSender{cfg: Config{Host: addr, Username: "u", Password: "p"}, timeout: timeout}
}

var testMsg = sluice.Message{From: "a@example.com", Rcpt: []string{"b@example.com"}, Raw: []byte("Subject: x\r\n\r\nbody\r\n")}

// #362: a server that never greets is abandoned at the overall deadline, as a
// transient failure, instead of waiting out the library's per-command timeout.
func TestSendAbortsAtOverallDeadline(t *testing.T) {
	s := testSender(stallingServer(t, false), 200*time.Millisecond)

	start := time.Now()
	err := s.Send(context.Background(), testMsg)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "bounded by the overall deadline")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, IsPermanent(err), "an aborted send stays re-sendable")
}

// The library resets the connection deadline before every command, so a stall
// after the greeting is the case a connection deadline alone would not bound.
func TestSendAbortsWhenStalledMidTransaction(t *testing.T) {
	s := testSender(stallingServer(t, true), 200*time.Millisecond)

	start := time.Now()
	err := s.Send(context.Background(), testMsg)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// The caller's cancellation stops a send even when the overall deadline is far
// away.
func TestSendHonoursCallerCancellation(t *testing.T) {
	s := testSender(stallingServer(t, true), time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	err := s.Send(ctx, testMsg)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
	assert.False(t, IsPermanent(err))
}

// The production constructor applies the overall deadline.
func TestNewSMTPSetsSendTimeout(t *testing.T) {
	snd, err := newSMTP(Config{Host: "127.0.0.1:1", Username: "u", Password: "p"})
	require.NoError(t, err)
	assert.Equal(t, sendTimeout, snd.(*smtpSender).timeout)
}
