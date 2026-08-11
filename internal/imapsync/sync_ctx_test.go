package imapsync_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// startHangingUpstream runs a raw IMAP server that completes the connect + LOGIN
// handshake normally but never answers the named command (e.g. "SELECT"): it holds
// the socket open and says nothing, the "accepted then silent" upstream go-imap's
// connect timeout does not cover. It closes `reached` the instant it receives the
// named command — the deterministic point at which that command is in flight — so a
// test can cancel exactly then, guaranteeing it exercises the command-phase unblock
// rather than (by a timing race) the connect-cancellation path. The `release`
// channel, closed by the caller, unblocks the parked handler at test end.
func startHangingUpstream(t *testing.T, hangOn string) (addr string, reached, release chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	reached = make(chan struct{})
	release = make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		// Advertise capabilities in the greeting so go-imap logs in without a separate
		// pre-login CAPABILITY round-trip; no LOGINDISABLED, so plain LOGIN is allowed.
		_, _ = io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fake ready\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			fields := strings.SplitN(line, " ", 3)
			if len(fields) < 2 {
				continue
			}
			tag, cmd := fields[0], strings.ToUpper(fields[1])
			if cmd == strings.ToUpper(hangOn) {
				close(reached) // the withheld command is now in flight
				<-release      // park here, answering nothing, until the test releases us
				return
			}
			switch cmd {
			case "CAPABILITY":
				_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
				_, _ = io.WriteString(conn, tag+" OK CAPABILITY completed\r\n")
			case "LOGOUT":
				_, _ = io.WriteString(conn, "* BYE\r\n"+tag+" OK LOGOUT completed\r\n")
				return
			default: // LOGIN, NOOP, … — anything but the parked command
				_, _ = fmt.Fprintf(conn, "%s OK %s completed\r\n", tag, cmd)
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), reached, release
}

// C32: Sync honors ctx when the upstream accepts the connection and then never
// answers the SELECT — the command phase go-imap does not bound. With ctx cancelled
// shortly after entry, Sync must unblock the in-flight SELECT and return promptly,
// not hang on it. The upstream stays connected the whole time, so a pass here cannot
// be an artifact of an already-closed connection or a ctx cancelled before entry.
func TestSyncHonorsContextOnHungUpstream(t *testing.T) {
	addr, reached, release := startHangingUpstream(t, "SELECT")
	defer close(release)

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel exactly when the SELECT is in flight (the server signals `reached`), so
	// the test provably exercises the command-phase unblock, not the connect path.
	go func() { <-reached; cancel() }()

	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := syncer.Sync(ctx); done <- err }()

	select {
	case err := <-done:
		require.Error(t, err, "a cancelled sync against a hung upstream returns an error")
		assert.Less(t, time.Since(start), 2*time.Second, "sync unblocked the hung SELECT instead of hanging")
	case <-time.After(5 * time.Second):
		t.Fatal("Sync did not return after ctx cancellation against a hung upstream")
	}
}

// C32 (on-demand entry point): OnDemandSync.Trigger runs Sync with the caller's
// context, so a bounded context from the STATUS wiring (OnDemandSyncTimeout in
// cmd/darbaan) bounds a hung on-demand pull too — the interactive path an agent
// reaches. Against an upstream that accepts login then never answers SELECT, a
// Trigger whose context is cancelled while the command is in flight must return
// promptly rather than block the session goroutine and wedge the coordinator's
// single-flight flag for the process lifetime.
func TestOnDemandTriggerHonorsContextOnHungUpstream(t *testing.T) {
	addr, reached, release := startHangingUpstream(t, "SELECT")
	defer close(release)

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	od := imapsync.NewOnDemandSync()
	od.Register("work", syncer, 0) // no debounce, so the trigger runs the pull

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-reached; cancel() }()

	done := make(chan error, 1)
	start := time.Now()
	go func() { _, _, err := od.Trigger(ctx, "work"); done <- err }()

	select {
	case err := <-done:
		require.Error(t, err, "a cancelled on-demand trigger against a hung upstream returns an error")
		assert.Less(t, time.Since(start), 2*time.Second, "the on-demand pull unblocked instead of wedging")
	case <-time.After(5 * time.Second):
		t.Fatal("Trigger did not return after ctx cancellation against a hung upstream")
	}
}

// C32 (connect phase): Sync honors ctx while the dial itself is blocked (a
// black-hole connect), abandoning it promptly on cancellation rather than waiting
// out the dialer's fixed timeout.
func TestSyncHonorsContextWhileConnecting(t *testing.T) {
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	dial := func() (*imapclient.Client, error) {
		<-blocked // the dial never completes until test cleanup
		return nil, fmt.Errorf("unreachable")
	}
	syncer := imapsync.New(dial, "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := syncer.Sync(ctx); done <- err }()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled, "a cancelled connect surfaces the cancellation")
		assert.Less(t, time.Since(start), 2*time.Second, "sync abandoned the blocked connect promptly")
	case <-time.After(5 * time.Second):
		t.Fatal("Sync did not abandon a blocked connect on ctx cancellation")
	}
}
