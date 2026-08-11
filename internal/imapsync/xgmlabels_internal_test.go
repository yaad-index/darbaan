package imapsync

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The raw label writer reports ErrNotXGM against a server with no X-GM-EXT-1
// (the in-process memserver), exercising the session mechanics over plaintext:
// dial → greeting → LOGIN → CAPABILITY → capability gate. The actual
// X-GM-LABELS STORE only runs on a Gmail backend and is live-verified.
func TestLabelStoreNotGmail(t *testing.T) {
	user := imapmemserver.NewUser("u", "p")
	require.NoError(t, user.Create("INBOX", nil))
	_, err := user.Append("INBOX", bytes.NewReader([]byte("Subject: x\r\n\r\ny")), &imap.AppendOptions{})
	require.NoError(t, err)
	mem := imapmemserver.New()
	mem.AddUser(user)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	ls := newLabelStore(
		func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) },
		"u", "p", "INBOX",
	)
	err = ls(1, 1, []string{"useless"}, nil)
	require.ErrorIs(t, err, ErrNotXGM)
}

// fakeXGM is a scripted raw IMAP server for the X-GM-LABELS write path: it
// advertises X-GM-EXT-1, answers SELECT with a configurable UIDVALIDITY, and
// records every command line it receives so a test can assert whether a UID STORE
// was ever dispatched. It speaks only the handful of commands newLabelStore issues.
type fakeXGM struct {
	ln          net.Listener
	uidValidity uint32
	mu          sync.Mutex
	cmds        []string
}

func newFakeXGM(t *testing.T, uidValidity uint32) *fakeXGM {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeXGM{ln: ln, uidValidity: uidValidity}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeXGM) addr() string { return f.ln.Addr().String() }

func (f *fakeXGM) record(cmd string) {
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	f.mu.Unlock()
}

// sawUIDStore reports whether any recorded command was a UID STORE — the side
// effect a stale-validity write must never reach.
func (f *fakeXGM) sawUIDStore() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(strings.ToUpper(c), "UID STORE") {
			return true
		}
	}
	return false
}

func (f *fakeXGM) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	_, _ = io.WriteString(conn, "* OK fakeXGM ready\r\n")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		fields := strings.SplitN(line, " ", 3)
		if len(fields) < 2 {
			continue
		}
		tag, cmd := fields[0], strings.ToUpper(fields[1])
		switch cmd {
		case "CAPABILITY":
			_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1 X-GM-EXT-1\r\n")
			_, _ = io.WriteString(conn, tag+" OK CAPABILITY completed\r\n")
		case "SELECT":
			if f.uidValidity != 0 { // 0 → answer SELECT with NO UIDVALIDITY response code
				_, _ = fmt.Fprintf(conn, "* OK [UIDVALIDITY %d] UIDs valid\r\n", f.uidValidity)
			}
			_, _ = io.WriteString(conn, tag+" OK [READ-WRITE] SELECT completed\r\n")
		case "LOGOUT":
			_, _ = io.WriteString(conn, "* BYE\r\n"+tag+" OK LOGOUT completed\r\n")
			return
		default: // LOGIN, UID STORE, …
			_, _ = io.WriteString(conn, tag+" OK completed\r\n")
		}
	}
}

// C9: the label writer refuses when the mailbox UIDVALIDITY no longer matches the
// one the message was recorded under, and it refuses BEFORE issuing any UID STORE —
// the same guard the plain-keyword path applies (WriteKeywords), at the same point
// (post-SELECT, pre-STORE). A stale UID must never reach a STORE against a reset
// mailbox, where it would label a different message. The assertion that no UID STORE
// reached the server is what would fail if the check were moved even one step later.
func TestLabelStoreRefusesStaleValidityBeforeStore(t *testing.T) {
	f := newFakeXGM(t, 4000) // the upstream mailbox is now at validity 4000
	ls := newLabelStore(
		func() (net.Conn, error) { return net.Dial("tcp", f.addr()) },
		"u", "p", "INBOX",
	)
	// The message was recorded under validity 3000 — the mailbox has since reset.
	err := ls(42, 3000, []string{"Important"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mailbox reset")
	assert.False(t, f.sawUIDStore(), "a stale-validity label write must not reach a UID STORE")
}

// C9 (match): when the mailbox UIDVALIDITY matches the recorded one, the label
// write proceeds and the UID STORE is issued.
func TestLabelStoreIssuesStoreOnMatchingValidity(t *testing.T) {
	f := newFakeXGM(t, 4000)
	ls := newLabelStore(
		func() (net.Conn, error) { return net.Dial("tcp", f.addr()) },
		"u", "p", "INBOX",
	)
	require.NoError(t, ls(42, 4000, []string{"Important"}, nil))
	assert.True(t, f.sawUIDStore(), "a matching-validity label write issues the UID STORE")
}

// C9 (unknown validity, both sides zero — the fail-open the guard must close): when
// the SELECT response carries no parseable UIDVALIDITY code (got 0) AND the record's
// stored validity is also 0 (a record predating the persisted field), the writer must
// refuse rather than read 0 == 0 as a match and STORE against an unconfirmed UID space.
func TestLabelStoreRefusesUnknownValidityBeforeStore(t *testing.T) {
	f := newFakeXGM(t, 0) // SELECT answers without a UIDVALIDITY response code
	ls := newLabelStore(
		func() (net.Conn, error) { return net.Dial("tcp", f.addr()) },
		"u", "p", "INBOX",
	)
	err := ls(42, 0, []string{"Important"}, nil) // record validity also unknown (0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unconfirmed mailbox validity")
	assert.False(t, f.sawUIDStore(), "an unconfirmed-validity label write must not reach a UID STORE")
}

// C9 (one side unknown): a known server validity but a zero recorded validity also
// refuses — the record's UID space cannot be confirmed against the mailbox, so it must
// not reach a UID STORE.
func TestLabelStoreRefusesZeroRecordValidity(t *testing.T) {
	f := newFakeXGM(t, 4000)
	ls := newLabelStore(
		func() (net.Conn, error) { return net.Dial("tcp", f.addr()) },
		"u", "p", "INBOX",
	)
	err := ls(42, 0, []string{"Important"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unconfirmed mailbox validity")
	assert.False(t, f.sawUIDStore(), "a zero recorded validity must not reach a UID STORE")
}

func TestSelectUIDValidity(t *testing.T) {
	assert.Equal(t, uint32(4000), selectUIDValidity([]string{"* OK [UIDVALIDITY 4000] UIDs valid"}))
	assert.Equal(t, uint32(1), selectUIDValidity([]string{"* 3 EXISTS", "* OK [uidvalidity 1] lower-case code"}))
	assert.Zero(t, selectUIDValidity([]string{"* 3 EXISTS", "* OK no validity code here"}), "absent code reads as 0 (fails the equality guard safe)")
	assert.Zero(t, selectUIDValidity([]string{"* OK [UIDVALIDITY notanumber] bad"}), "unparseable code reads as 0")
}

func TestImapQuote(t *testing.T) {
	require.Equal(t, `"useless"`, imapQuote("useless"))
	require.Equal(t, `"a b"`, imapQuote("a b"))
	require.Equal(t, `"a\"b"`, imapQuote(`a"b`))
	require.Equal(t, `"a\\b"`, imapQuote(`a\b`))
	require.Equal(t, `"x" "y z"`, labelList([]string{"x", "y z"}))
}
