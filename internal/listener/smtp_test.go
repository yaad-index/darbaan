package listener_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/listener"
	"github.com/yaad-index/darbaan/internal/sluice"
)

const (
	testUser = "agent"
	testPass = "s3cret"
)

var testAuth = listener.SingleAuth(testUser, testPass)

func newSluice(t *testing.T) sluice.MessageStore {
	t.Helper()
	al, err := audit.New("null", "")
	require.NoError(t, err)
	q, err := sluice.New("bbolt", filepath.Join(t.TempDir(), "sluice.db"), al)
	require.NoError(t, err)
	t.Cleanup(func() { _ = q.Close(); _ = al.Close() })
	return q
}

// startServer serves the SMTP face on a random localhost port and returns its
// address. The server is closed at test end.
func startServer(t *testing.T, cfg listener.ServerConfig, q listener.Enqueuer) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewServer(cfg, testAuth, q, nil)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func startServerRoute(t *testing.T, cfg listener.ServerConfig, q listener.Enqueuer, route listener.Router) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewServer(cfg, testAuth, q, route)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func startServerAuth(t *testing.T, cfg listener.ServerConfig, q listener.Enqueuer, route listener.Router, auth *listener.Auth) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := listener.NewServer(cfg, auth, q, route)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// ADR 0027 send-scoping: an agent may originate mail only as an inbox it has send
// on; a read-only inbox is rejected at MAIL FROM (fail-closed). An unmatched From
// routes to the agent's own default_inbox (per-agent catch-all).
func TestSubmitSendScoping(t *testing.T) {
	q := newSluice(t)
	route := func(from, catchAll string) (string, bool) {
		switch from {
		case "work@x.test":
			return "work", true
		case "personal@x.test":
			return "personal", true
		}
		if catchAll != "" {
			return catchAll, true // per-agent catch-all
		}
		return "", false
	}
	// agent-a reads work+personal but may send only as work; default_inbox = work.
	auth := listener.NewAuth([]listener.Principal{{
		Name: "agent-a", Password: "pw", DefaultInbox: "work",
		Reads: map[string]bool{"work": true, "personal": true},
		Sends: map[string]bool{"work": true},
	}})
	addr := startServerAuth(t, listener.ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
	}, q, route, auth)

	dial := func() *smtp.Client {
		c, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
		require.NoError(t, err)
		require.NoError(t, c.Auth(sasl.NewPlainClient("", "agent-a", "pw")))
		return c
	}

	// A sendable identity is accepted.
	c := dial()
	require.NoError(t, c.Mail("work@x.test", nil))
	_ = c.Close()

	// An identity the agent may read but not send is rejected at MAIL FROM.
	c = dial()
	require.Error(t, c.Mail("personal@x.test", nil), "read-only inbox cannot originate mail")
	_ = c.Close()

	// An unmatched From routes to the agent's default_inbox (work), which it may
	// send as → accepted and stamped with that inbox.
	c = dial()
	const raw = "From: stranger@elsewhere.test\r\nTo: d@y.test\r\n\r\nbody\r\n"
	require.NoError(t, c.SendMail("stranger@elsewhere.test", []string{"d@y.test"}, strings.NewReader(raw)))
	_ = c.Quit()
	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	full, err := q.Get(metas[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "work", full.Inbox, "unmatched From routed to the agent's default inbox")
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestSubmitOverTLSEnqueuesOnePending is the acceptance test: an authenticated
// submission over STARTTLS yields exactly one queued pending message, with no
// upstream send path in the binary at all.
func TestSubmitOverTLSEnqueuesOnePending(t *testing.T) {
	q := newSluice(t)
	addr := startServer(t, listener.ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
	}, q)

	c, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	require.NoError(t, c.Auth(sasl.NewPlainClient("", testUser, testPass)))

	const raw = "From: agent@local\r\nTo: dest@example.test\r\nSubject: Trapped\r\n\r\nbody-marker-42\r\n"
	require.NoError(t, c.SendMail("agent@local", []string{"dest@example.test"}, strings.NewReader(raw)))
	require.NoError(t, c.Quit())

	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, sluice.StatusPending, metas[0].Status)
	assert.Equal(t, testUser, metas[0].Agent)

	full, err := q.Get(metas[0].ID)
	require.NoError(t, err)
	assert.Contains(t, string(full.Raw), "body-marker-42")
	assert.Equal(t, "agent@local", full.From)
	assert.Equal(t, []string{"dest@example.test"}, full.Rcpt)
}

// ADR 0023: the submission face routes From to an inbox — a matched From stamps
// the inbox on the queued message; an unmatched From with no default is refused
// at MAIL FROM.
func TestSubmitRoutesFromToInbox(t *testing.T) {
	q := newSluice(t)
	route := func(from, _ string) (string, bool) {
		if from == "work@company.test" {
			return "work", true
		}
		return "", false // unmatched, no default → refuse
	}
	addr := startServerRoute(t, listener.ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
	}, q, route)

	c, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Auth(sasl.NewPlainClient("", testUser, testPass)))

	// Matched From → the routed inbox is stamped on the queued message.
	const raw = "From: work@company.test\r\nTo: d@x.test\r\nSubject: s\r\n\r\nbody\r\n"
	require.NoError(t, c.SendMail("work@company.test", []string{"d@x.test"}, strings.NewReader(raw)))
	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	full, err := q.Get(metas[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "work", full.Inbox)

	// Unmatched From with no default → refused at MAIL FROM (nothing else queued).
	require.Error(t, c.Mail("stranger@elsewhere.test", nil))
	metas, err = q.List()
	require.NoError(t, err)
	assert.Len(t, metas, 1)
}

// failingEnqueuer simulates a transient queue-write failure (locked DB / disk
// hiccup) and carries an internal error string that must never reach the agent.
type failingEnqueuer struct{}

func (failingEnqueuer) Enqueue(sluice.Submission) (sluice.Message, error) {
	return sluice.Message{}, errors.New("bbolt: database is locked (internal detail)")
}

// C12: a failed Enqueue must map to a transient 4xx so a correct client retries
// instead of dropping the mail, and the internal error detail must not leak to
// the agent.
func TestSubmitQueueFailureIsTransientAndOpaque(t *testing.T) {
	addr := startServer(t, listener.ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
	}, failingEnqueuer{})

	c, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Auth(sasl.NewPlainClient("", testUser, testPass)))

	const raw = "From: agent@local\r\nTo: d@x.test\r\n\r\nbody\r\n"
	err = c.SendMail("agent@local", []string{"d@x.test"}, strings.NewReader(raw))
	require.Error(t, err)

	var se *smtp.SMTPError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, 451, se.Code, "transient queue failure must be a 4xx (retry), not a 5xx (drop)")
	assert.Equal(t, smtp.EnhancedCode{4, 3, 0}, se.EnhancedCode)
	assert.NotContains(t, se.Message, "database is locked", "internal error must not leak to the agent")
	assert.NotContains(t, se.Message, "internal detail")
}

func TestPlaintextRequiresAuth(t *testing.T) {
	q := newSluice(t)
	addr := startServer(t, listener.ServerConfig{AllowInsecure: true}, q)

	c, err := smtp.Dial(addr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	// MAIL before AUTH must be refused.
	require.Error(t, c.Mail("agent@local", nil))

	metas, err := q.List()
	require.NoError(t, err)
	assert.Empty(t, metas)
}

func TestBadCredentialRejected(t *testing.T) {
	q := newSluice(t)
	addr := startServer(t, listener.ServerConfig{AllowInsecure: true}, q)

	c, err := smtp.Dial(addr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	require.Error(t, c.Auth(sasl.NewPlainClient("", testUser, "wrong")))
}

func TestNewServerRequiresTLS(t *testing.T) {
	q := newSluice(t)
	_, err := listener.NewServer(listener.ServerConfig{}, testAuth, q, nil)
	require.Error(t, err)

	_, err = listener.NewServer(listener.ServerConfig{AllowInsecure: true}, testAuth, q, nil)
	require.NoError(t, err)
}
