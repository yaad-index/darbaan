package imapsync

import (
	"bytes"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
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

func TestImapQuote(t *testing.T) {
	require.Equal(t, `"useless"`, imapQuote("useless"))
	require.Equal(t, `"a b"`, imapQuote("a b"))
	require.Equal(t, `"a\"b"`, imapQuote(`a"b`))
	require.Equal(t, `"a\\b"`, imapQuote(`a\b`))
	require.Equal(t, `"x" "y z"`, labelList([]string{"x", "y z"}))
}
