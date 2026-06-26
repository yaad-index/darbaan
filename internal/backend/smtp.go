package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/yaad-index/darbaan/internal/sluice"
)

func init() {
	Register("smtp", newSMTP)
}

// smtpSender delivers messages to an upstream SMTP submission server (Gmail =
// smtp.gmail.com) over STARTTLS with AUTH PLAIN, verifying the server
// certificate. A vetted client (emersion/go-smtp), no hand-rolled SMTP
// (ADR 0014).
type smtpSender struct {
	cfg Config
}

func newSMTP(cfg Config) (Sender, error) {
	// Fail closed: an smtp sender with missing host or credentials must not be
	// constructed (it would silently never deliver).
	if cfg.Host == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("backend: smtp sender requires smtp-host, smtp-username, and DARBAAN_SMTP_PASSWORD")
	}
	if _, _, err := net.SplitHostPort(cfg.Host); err != nil {
		return nil, fmt.Errorf("backend: smtp-host must be host:port, got %q: %w", cfg.Host, err)
	}
	return &smtpSender{cfg: cfg}, nil
}

func (s *smtpSender) Send(_ context.Context, msg sluice.Message) error {
	host, _, _ := net.SplitHostPort(s.cfg.Host)

	// ServerName set + no InsecureSkipVerify ⇒ the server certificate is
	// verified against the host (ADR 0009: verify TLS).
	c, err := smtp.DialStartTLS(s.cfg.Host, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("backend: dial %s: %w", s.cfg.Host, err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", s.cfg.Username, s.cfg.Password)); err != nil {
		return fmt.Errorf("backend: auth: %w", err)
	}

	// Release the edited body if a human approver amended it (ADR 0004),
	// otherwise the original.
	body := msg.Raw
	if msg.Released != nil {
		body = msg.Released
	}
	// Return the SendMail error wrapped: errors.As still recovers the
	// *smtp.SMTPError so IsPermanent can classify the 5xx/4xx code.
	if err := c.SendMail(msg.From, msg.Rcpt, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("backend: send: %w", err)
	}
	return nil
}
