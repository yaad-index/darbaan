package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

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
	// timeout bounds a whole send: dial, STARTTLS, auth and submission (#362).
	timeout time.Duration
}

// sendTimeout is the overall deadline for one send. The client library only
// bounds each step (5 minutes per command, 12 for the body), so without this a
// stalled server can hold a send for tens of minutes. It is sized for a large
// message over a slow uplink: a 25 MB body at 1 Mbit/s takes about 3.5 minutes.
const sendTimeout = 5 * time.Minute

func newSMTP(cfg Config) (Sender, error) {
	// Fail closed: an smtp sender with missing host or credentials must not be
	// constructed (it would silently never deliver).
	if cfg.Host == "" || cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("backend: smtp sender requires smtp-host, smtp-username, and DARBAAN_SMTP_PASSWORD")
	}
	if _, _, err := net.SplitHostPort(cfg.Host); err != nil {
		return nil, fmt.Errorf("backend: smtp-host must be host:port, got %q: %w", cfg.Host, err)
	}
	return &smtpSender{cfg: cfg, timeout: sendTimeout}, nil
}

func (s *smtpSender) Send(ctx context.Context, msg sluice.Message) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	err := s.send(ctx, msg)
	if err != nil && ctx.Err() != nil {
		// The deadline or the caller's cancellation closed the connection; say
		// so rather than surfacing the closed-connection error it caused. Not an
		// *smtp.SMTPError, so IsPermanent treats it as transient.
		return fmt.Errorf("backend: send to %s aborted: %w", s.cfg.Host, ctx.Err())
	}
	return err
}

func (s *smtpSender) send(ctx context.Context, msg sluice.Message) error {
	host, _, _ := net.SplitHostPort(s.cfg.Host)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.cfg.Host)
	if err != nil {
		return fmt.Errorf("backend: dial %s: %w", s.cfg.Host, err)
	}
	// The library resets the connection deadline before every command, so a
	// deadline set here would not hold. Closing the connection when ctx ends is
	// what bounds the whole send, wherever it is.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// ServerName set + no InsecureSkipVerify ⇒ the server certificate is
	// verified against the host (ADR 0009: verify TLS).
	c, err := smtp.NewClientStartTLS(conn, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("backend: dial %s: %w", s.cfg.Host, err) // it closed conn
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
