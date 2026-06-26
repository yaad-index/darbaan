package listener_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

var testCred = listener.Credential{Username: "agent", Password: "s3cret"}

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
	srv, err := listener.NewServer(cfg, testCred, q)
	require.NoError(t, err)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
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

	require.NoError(t, c.Auth(sasl.NewPlainClient("", testCred.Username, testCred.Password)))

	const raw = "From: agent@local\r\nTo: dest@example.test\r\nSubject: Trapped\r\n\r\nbody-marker-42\r\n"
	require.NoError(t, c.SendMail("agent@local", []string{"dest@example.test"}, strings.NewReader(raw)))
	require.NoError(t, c.Quit())

	metas, err := q.List()
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, sluice.StatusPending, metas[0].Status)
	assert.Equal(t, testCred.Username, metas[0].Agent)

	full, err := q.Get(metas[0].ID)
	require.NoError(t, err)
	assert.Contains(t, string(full.Raw), "body-marker-42")
	assert.Equal(t, "agent@local", full.From)
	assert.Equal(t, []string{"dest@example.test"}, full.Rcpt)
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

	require.Error(t, c.Auth(sasl.NewPlainClient("", testCred.Username, "wrong")))
}

func TestNewServerRequiresTLS(t *testing.T) {
	q := newSluice(t)
	_, err := listener.NewServer(listener.ServerConfig{}, testCred, q)
	require.Error(t, err)

	_, err = listener.NewServer(listener.ServerConfig{AllowInsecure: true}, testCred, q)
	require.NoError(t, err)
}
