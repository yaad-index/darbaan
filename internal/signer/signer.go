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

// Verify reports whether raw carries a valid DKIM signature from Darbaan's own
// bounce selector/domain — the trust check for the inbound bounce-spoof guard
// (ADR 0024, realizing ADR 0007's quarantine). Darbaan signs its own bounces, so
// it can verify them: the key may be pinned out-of-band rather than published in
// DNS, so the lookup is injected and resolves ONLY Darbaan's own
// `<selector>._domainkey.<domain>` against the in-memory public key. A signature
// from any other domain/selector has no key to check against and does not count,
// and a forged `d=<our domain>` signature fails because it wasn't made with our
// key. Returns true only if some signature with d=<our domain> verifies; an
// unsigned message returns false. err is non-nil only on malformed input, never
// for an unverified message (that is a clean false).
func (s *Signer) Verify(raw []byte) (bool, error) {
	want := s.opts.Selector + "._domainkey." + s.opts.Domain
	record := s.PublicKeyTXT()
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			if domain == want {
				return []string{record}, nil
			}
			return nil, nil // foreign selector/domain: no key, so its signature can't verify
		},
	})
	if err != nil {
		return false, fmt.Errorf("signer: dkim verify: %w", err)
	}
	for _, v := range vs {
		if v.Err == nil && v.Domain == s.opts.Domain {
			return true, nil
		}
	}
	return false, nil
}
