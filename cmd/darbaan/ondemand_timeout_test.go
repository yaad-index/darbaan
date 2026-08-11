package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// startHungIMAP runs a raw IMAP server that completes the connect + LOGIN handshake
// but never answers a SELECT: the "accepted then silent" upstream whose command
// phase go-imap's connect timeout does not cover. It is the production hazard the
// on-demand bound exists for. Closed at test end via the returned stop func.
func startHungIMAP(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		_, _ = io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] hung ready\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
			if len(fields) < 2 {
				continue
			}
			tag, cmd := fields[0], strings.ToUpper(fields[1])
			if cmd == "SELECT" {
				<-done // park, answering nothing, until the test tears down
				return
			}
			switch cmd {
			case "CAPABILITY":
				_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"+tag+" OK done\r\n")
			default: // LOGIN, NOOP, …
				_, _ = fmt.Fprintf(conn, "%s OK %s done\r\n", tag, cmd)
			}
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close() }
}

func hungDial(addr string) imapsync.DialFunc {
	return func() (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		if err := c.Login("u", "p").Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}
}

func onDemandFixture(t *testing.T, dial imapsync.DialFunc) *imapsync.OnDemandSync {
	t.Helper()
	store, err := inbound.New("bbolt", filepath.Join(t.TempDir(), "inbound.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	state, err := imapsync.NewStateStore(filepath.Join(t.TempDir(), "sync.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = state.Close() })
	syncer := imapsync.New(dial, "INBOX", "agent", inbound.DefaultInbox, store, state, 0)
	od := imapsync.NewOnDemandSync()
	od.Register("work", syncer, 0) // no debounce
	return od
}

// onDemandSyncNow must bound a STATUS pull against an upstream that accepts login and
// then hangs on SELECT: it returns within the deadline rather than blocking the
// caller forever. This is the wiring the finding was about — it fails (hits the
// watchdog) if the bound is removed, so a green result proves the deadline is applied
// at this call site, not merely that Sync would honour some other context. A deadline
// reached mid-command is a deferral, so the returned error is nil even though the
// command-phase cancellation surfaces internally as a closed-connection error, not
// context.DeadlineExceeded — the ctx.Err() classification catches that case.
func TestOnDemandSyncNowBoundsHungUpstream(t *testing.T) {
	addr, stop := startHungIMAP(t)
	defer stop()
	od := onDemandFixture(t, hungDial(addr))

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- onDemandSyncNow(od, "work", 300*time.Millisecond) }()

	select {
	case err := <-done:
		assert.NoError(t, err, "a deadline reached mid-pull is a deferral, swallowed, not a failure")
		assert.Less(t, time.Since(start), 3*time.Second, "the pull was bounded by its deadline, not left hanging")
	case <-time.After(5 * time.Second):
		t.Fatal("onDemandSyncNow did not return: the deadline was not applied at this call site")
	}
}

// A genuine pull error, with the deadline NOT reached, is returned rather than
// swallowed — the deferral classification keys on ctx.Err(), so it must not hide a
// real failure that happened well within budget.
func TestOnDemandSyncNowReturnsRealError(t *testing.T) {
	od := onDemandFixture(t, func() (*imapclient.Client, error) {
		return nil, fmt.Errorf("dial refused")
	})
	err := onDemandSyncNow(od, "work", 5*time.Second)
	require.Error(t, err, "a non-deadline failure is surfaced, not swallowed as a deferral")
	assert.Contains(t, err.Error(), "connect")
}
