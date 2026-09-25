package imapsync_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// fakeKwServer is a scripted raw IMAP server for the plain-keyword STORE path
// (WriteKeywords). It exists because the in-process memserver always answers SELECT
// with a real UIDVALIDITY, so it cannot produce the "server omitted the response
// code" case at all — the zero that pairs with a zero-validity record. When
// uidValidity is 0 this server omits the UIDVALIDITY response code entirely, which
// is what makes go-imap yield sel.UIDValidity == 0. It records every command line so
// a test can assert whether a STORE was ever dispatched.
type fakeKwServer struct {
	ln          net.Listener
	uidValidity uint32
	mu          sync.Mutex
	cmds        []string
}

func newFakeKwServer(t *testing.T, uidValidity uint32) *fakeKwServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeKwServer{ln: ln, uidValidity: uidValidity}
	go f.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeKwServer) addr() string { return f.ln.Addr().String() }

func (f *fakeKwServer) record(cmd string) {
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	f.mu.Unlock()
}

// sawCmd reports whether any recorded command line contains the given verb.
func (f *fakeKwServer) sawCmd(verb string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(strings.ToUpper(c), verb) {
			return true
		}
	}
	return false
}

// acceptLoop serves every connection: WriteKeywords dials a fresh session per call,
// so a single-Accept server would hang the second row of a table test.
func (f *fakeKwServer) acceptLoop() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.serve(conn)
	}
}

func (f *fakeKwServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	_, _ = io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1] fakeKwServer ready\r\n")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		fields := strings.SplitN(line, " ", 2)
		if len(fields) < 2 {
			continue
		}
		tag, rest := fields[0], strings.ToUpper(fields[1])
		switch {
		case strings.HasPrefix(rest, "CAPABILITY"):
			_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1\r\n"+tag+" OK CAPABILITY completed\r\n")
		case strings.HasPrefix(rest, "SELECT"):
			_, _ = io.WriteString(conn, "* FLAGS (\\Seen \\Answered)\r\n")
			_, _ = io.WriteString(conn, "* 1 EXISTS\r\n")
			_, _ = io.WriteString(conn, "* OK [UIDNEXT 43] Predicted next UID\r\n")
			if f.uidValidity != 0 { // 0 → answer SELECT with NO UIDVALIDITY response code
				_, _ = fmt.Fprintf(conn, "* OK [UIDVALIDITY %d] UIDs valid\r\n", f.uidValidity)
			}
			_, _ = io.WriteString(conn, tag+" OK [READ-WRITE] SELECT completed\r\n")
		case strings.HasPrefix(rest, "LOGOUT"):
			_, _ = io.WriteString(conn, "* BYE\r\n"+tag+" OK LOGOUT completed\r\n")
			return
		default: // LOGIN, UID STORE, NOOP, …
			_, _ = io.WriteString(conn, tag+" OK completed\r\n")
		}
	}
}

// seedRecord stores an upstream-pulled record with the given UID/validity and
// returns its id. AddSynced enforces only a non-zero UpstreamUID — it does not
// check UIDValidity — which is why a zero-validity record is a real population
// rather than a hypothetical one.
func seedRecord(t *testing.T, store inbound.InboundStore, uid, validity uint32) string {
	t.Helper()
	_, m, err := store.AddSynced(inbound.Delivery{
		Owner:       "agent",
		Inbox:       inbound.DefaultInbox,
		UpstreamUID: uid,
		UIDValidity: validity,
		Raw:         []byte("Subject: x\r\n\r\ny"),
	})
	require.NoError(t, err)
	require.Equal(t, validity, m.UIDValidity, "the store must persist the validity verbatim, zero included")
	return m.ID
}

// #257: the plain-keyword STORE path refuses when the mailbox validity is unknown on
// EITHER side, and refuses BEFORE issuing any STORE. The both-zeros row is the one
// the old bare inequality let through: it read 0 != 0 as "matches" and stored against
// a UID space the server never confirmed. The mirror of this guard on the
// X-GM-LABELS path landed in #256.
func TestWriteKeywordsRefusesUnknownValidityBeforeStore(t *testing.T) {
	for _, tc := range []struct {
		name           string
		serverValidity uint32
		recordValidity uint32
	}{
		// The regression: both sides zero. Old code proceeded to STORE here.
		{"both zero", 0, 0},
		// Server omits the code; the record knows its validity.
		{"server zero only", 0, 4000},
		// A legacy record predating the persisted field, against a healthy server —
		// the population #255 backfills.
		{"record zero only", 4000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeKwServer(t, tc.serverValidity)
			store := newInbound(t)
			id := seedRecord(t, store, 42, tc.recordValidity)
			syncer := imapsync.New(dialFor(f.addr()), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)

			err := syncer.WriteKeywords("agent", inbound.DefaultInbox, id, []string{"handled"}, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "unconfirmed mailbox validity")
			assert.False(t, f.sawCmd("STORE"), "a write with unconfirmed validity must not reach a STORE")
			// Without this the False above would also pass if the session never got
			// off the ground — an unreached guard and a firing guard look identical
			// from the STORE side alone.
			assert.True(t, f.sawCmd("SELECT"), "the guard must sit post-SELECT, so SELECT must have been issued")
		})
	}
}

// Positive control for the test above: with validity confirmed and matching on both
// sides, the same harness carries a STORE through. This is what fails if the new
// guard is too broad, and it proves the fake server can dispatch a STORE at all.
func TestWriteKeywordsIssuesStoreOnConfirmedMatchingValidity(t *testing.T) {
	f := newFakeKwServer(t, 4000)
	store := newInbound(t)
	id := seedRecord(t, store, 42, 4000)
	syncer := imapsync.New(dialFor(f.addr()), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)

	require.NoError(t, syncer.WriteKeywords("agent", inbound.DefaultInbox, id, []string{"handled"}, nil))
	assert.True(t, f.sawCmd("STORE"), "a confirmed, matching-validity write issues the STORE")
}
