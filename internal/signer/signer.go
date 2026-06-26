package signer

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/emersion/go-msgauth/dkim"
)

// Signer signs Darbaan-issued bounces with DKIM (RFC 6376; ed25519 per RFC 8463)
// so an agent holding only the pinned public key trusts only bounces Darbaan
// produced (ADR 0007). The private key is held in memory only.
type Signer struct {
	opts   dkim.SignOptions
	pubKey ed25519.PublicKey
}

// New loads the PEM-encoded ed25519 private key at keyFile and builds a Signer
// for the selector and domain. It fails closed: a missing, unreadable, or
// non-ed25519 key is an error, so Darbaan never emits an unsigned bounce
// (ADR 0007). The key is read once and kept in memory only — the path is
// config, the file is the secret (ADR 0012); the key is never logged.
func New(keyFile, selector, domain string) (*Signer, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("signer: dkim-key-file is required for bounce signing")
	}
	if selector == "" || domain == "" {
		return nil, fmt.Errorf("signer: dkim-selector and dkim-domain are required")
	}
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("signer: read key file: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signer: %s is not PEM-encoded", keyFile)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signer: parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signer: key is %T, want ed25519 (RFC 8463)", key)
	}

	return &Signer{
		opts: dkim.SignOptions{
			Domain:                 domain,
			Selector:               selector,
			Signer:                 priv,
			Hash:                   crypto.SHA256,
			HeaderCanonicalization: dkim.CanonicalizationRelaxed,
			BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		},
		pubKey: priv.Public().(ed25519.PublicKey),
	}, nil
}

// Sign returns the message with a prepended DKIM-Signature header.
func (s *Signer) Sign(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := dkim.Sign(&buf, bytes.NewReader(raw), &s.opts); err != nil {
		return nil, fmt.Errorf("signer: dkim sign: %w", err)
	}
	return buf.Bytes(), nil
}

// PublicKeyTXT returns the DKIM public-key record — the value an operator
// publishes at <selector>._domainkey.<domain> (or pins to the agent
// out-of-band) so the agent can verify Darbaan's bounces.
func (s *Signer) PublicKeyTXT() string {
	return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(s.pubKey)
}
