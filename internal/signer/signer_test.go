package signer_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/signer"
)

func writeKey(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

func writeEd25519(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return writeKey(t, priv)
}

func TestSignAndVerifyWithPinnedKey(t *testing.T) {
	s, err := signer.New(writeEd25519(t), "darbaan", "darbaan.test")
	require.NoError(t, err)

	msg := []byte("From: MAILER-DAEMON@darbaan.test\r\nTo: a@b.test\r\nSubject: x\r\n\r\nbody\r\n")
	signed, err := s.Sign(msg)
	require.NoError(t, err)
	assert.Contains(t, string(signed), "DKIM-Signature:")

	// Agent-side verification against the pinned key (no DNS — LookupTXT returns
	// the record from PublicKeyTXT).
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			require.Equal(t, "darbaan._domainkey.darbaan.test", domain)
			return []string{s.PublicKeyTXT()}, nil
		},
	})
	require.NoError(t, err)
	require.Len(t, vs, 1)
	require.NoError(t, vs[0].Err)
	assert.Equal(t, "darbaan.test", vs[0].Domain)
}

func TestVerifyFailsOnTamper(t *testing.T) {
	s, err := signer.New(writeEd25519(t), "darbaan", "darbaan.test")
	require.NoError(t, err)
	signed, err := s.Sign([]byte("From: m@darbaan.test\r\nSubject: x\r\n\r\nbody\r\n"))
	require.NoError(t, err)

	tampered := bytes.Replace(signed, []byte("body"), []byte("evil"), 1)
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(tampered), &dkim.VerifyOptions{
		LookupTXT: func(string) ([]string, error) { return []string{s.PublicKeyTXT()}, nil },
	})
	require.NoError(t, err)
	require.Len(t, vs, 1)
	assert.Error(t, vs[0].Err) // body changed → signature no longer verifies
}

func TestVerifyOwnSignature(t *testing.T) {
	s, err := signer.New(writeEd25519(t), "darbaan", "darbaan.test")
	require.NoError(t, err)
	signed, err := s.Sign([]byte("From: MAILER-DAEMON@darbaan.test\r\nSubject: x\r\n\r\nbody\r\n"))
	require.NoError(t, err)

	ok, err := s.Verify(signed)
	require.NoError(t, err)
	assert.True(t, ok) // our own signature verifies against our pinned key
}

func TestVerifyRejectsUnsignedTamperedAndForeign(t *testing.T) {
	s, err := signer.New(writeEd25519(t), "darbaan", "darbaan.test")
	require.NoError(t, err)

	// unsigned: no DKIM-Signature → not trusted
	ok, err := s.Verify([]byte("From: spoof@evil.test\r\nSubject: Returned mail\r\n\r\nfake bounce\r\n"))
	require.NoError(t, err)
	assert.False(t, ok)

	// tampered after signing → signature no longer verifies
	signed, err := s.Sign([]byte("From: m@darbaan.test\r\nSubject: x\r\n\r\nbody\r\n"))
	require.NoError(t, err)
	tampered := bytes.Replace(signed, []byte("body"), []byte("evil"), 1)
	ok, err = s.Verify(tampered)
	require.NoError(t, err)
	assert.False(t, ok)

	// signed by a DIFFERENT domain's key (d= not ours) → no key to check, not trusted
	other, err := signer.New(writeEd25519(t), "darbaan", "other.test")
	require.NoError(t, err)
	foreign, err := other.Sign([]byte("From: m@other.test\r\nSubject: x\r\n\r\nbody\r\n"))
	require.NoError(t, err)
	ok, err = s.Verify(foreign)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPublicKeyTXTFormat(t *testing.T) {
	s, err := signer.New(writeEd25519(t), "sel", "dom")
	require.NoError(t, err)
	txt := s.PublicKeyTXT()
	assert.Contains(t, txt, "v=DKIM1")
	assert.Contains(t, txt, "k=ed25519")
	assert.Contains(t, txt, "p=")
}

func TestFailClosed(t *testing.T) {
	_, err := signer.New("", "s", "d")
	require.Error(t, err) // no key file

	_, err = signer.New(filepath.Join(t.TempDir(), "nope.pem"), "s", "d")
	require.Error(t, err) // missing file

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = signer.New(writeKey(t, rsaKey), "s", "d")
	require.Error(t, err) // non-ed25519 key rejected
}
