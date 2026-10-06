package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// scriptedServer is a plain SMTP server that accepts one transaction and then
// does what end says once it has read the body's final dot: reply with a
// line, or hang up with no reply. dropAtRcpt hangs up on RCPT instead.
func scriptedServer(t *testing.T, end string, dropAtRcpt bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 test ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250 test")
			case strings.HasPrefix(cmd, "MAIL"):
				write("250 ok")
			case strings.HasPrefix(cmd, "RCPT"):
				if dropAtRcpt {
					return
				}
				write("250 ok")
			case cmd == "DATA":
				write("354 go ahead")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
				}
				if end == "" {
					return // the body's end arrived; no final reply
				}
				write(end)
				if strings.HasPrefix(end, "250") {
					return // accepted, then the connection drops
				}
			default:
				write("250 ok")
			}
		}
	}()
	return ln.Addr().String()
}

func runTransact(t *testing.T, addr string) error {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	c := smtp.NewClient(conn)
	defer func() { _ = c.Close() }()
	return transact(c, "a@example.com", []string{"b@example.com"}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"))
}

// The body's end reached the server and no final reply came: the message may
// have been delivered, so the outcome is unknown, not a transient failure.
func TestNoFinalReplyIsOutcomeUnknown(t *testing.T) {
	err := runTransact(t, scriptedServer(t, "", false))
	require.Error(t, err)
	assert.ErrorIs(t, err, sluice.ErrOutcomeUnknown)
	assert.False(t, IsPermanent(err))
}

// A server that answers at close decides the outcome: a 5xx is permanent and a
// 4xx transient, neither unknown.
func TestAReplyAtCloseKeepsItsClass(t *testing.T) {
	err := runTransact(t, scriptedServer(t, "550 5.7.1 rejected", false))
	require.Error(t, err)
	assert.True(t, IsPermanent(err))
	assert.NotErrorIs(t, err, sluice.ErrOutcomeUnknown)

	err = runTransact(t, scriptedServer(t, "451 4.3.0 try later", false))
	require.Error(t, err)
	assert.False(t, IsPermanent(err))
	assert.NotErrorIs(t, err, sluice.ErrOutcomeUnknown)
	var se *smtp.SMTPError
	require.True(t, errors.As(err, &se))
	assert.Equal(t, 451, se.Code)
}

// A 250 at close is a delivered message, even when the connection drops
// right after it.
func TestASuccessAtCloseIsSentWhateverFollows(t *testing.T) {
	assert.NoError(t, runTransact(t, scriptedServer(t, "250 2.0.0 queued", false)))
}

// A failure before the body's end is an ordinary failure: the server cannot
// have accepted a message whose data never ended.
func TestAFailureBeforeTheBodyIsNotUnknown(t *testing.T) {
	err := runTransact(t, scriptedServer(t, "250 ok", true))
	require.Error(t, err)
	assert.NotErrorIs(t, err, sluice.ErrOutcomeUnknown)
	assert.False(t, IsPermanent(err))
}

// A deadline that cut off the final reply leaves the outcome unknown: Send
// does not turn it into an aborted, re-sendable failure. Any other failure
// under a dead context is reported as aborted.
func TestADeadlineDoesNotHideAnUnknownOutcome(t *testing.T) {
	unknown := fmt.Errorf("backend: send: %w: %w", sluice.ErrOutcomeUnknown, net.ErrClosed)
	err := sendResult(unknown, context.DeadlineExceeded, "smtp.example:587")
	assert.ErrorIs(t, err, sluice.ErrOutcomeUnknown)

	err = sendResult(fmt.Errorf("backend: send: %w", net.ErrClosed), context.DeadlineExceeded, "smtp.example:587")
	assert.NotErrorIs(t, err, sluice.ErrOutcomeUnknown)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
