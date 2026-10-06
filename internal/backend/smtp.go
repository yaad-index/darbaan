package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf8"

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
	return sendResult(s.send(ctx, msg), ctx.Err(), s.cfg.Host)
}

// sendResult is the error Send returns for err, the send's own error, when
// ctxErr is the send context's error and host the server's.
func sendResult(err, ctxErr error, host string) error {
	if errors.Is(err, sluice.ErrOutcomeUnknown) {
		// The deadline or a cancellation cut the final reply off: the server
		// may have accepted the message, so this is not an aborted send.
		return err
	}
	if err != nil && ctxErr != nil {
		// The deadline or the caller's cancellation closed the connection; say
		// so rather than surfacing the closed-connection error it caused. Not an
		// *smtp.SMTPError, so IsPermanent treats it as transient.
		return fmt.Errorf("backend: send to %s aborted: %w", host, ctxErr)
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
	// The error stays wrapped: errors.As still recovers the *smtp.SMTPError
	// so IsPermanent can classify the 5xx/4xx code. No QUIT follows a
	// delivered message, so nothing after the final reply can fail it.
	if err := transact(c, msg.From, msg.Rcpt, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("backend: send: %w", err)
	}
	return nil
}

// transact runs one SMTP mail transaction step by step, so it can tell where
// a failure happened (ADR 0039 section 3):
//
//   - a failure before the body is closed is an ordinary failure: the server
//     never saw the end of the data, so it cannot have accepted the message;
//   - at close, a reply decides it: a 5xx stays permanent and a 4xx transient,
//     both as *smtp.SMTPError;
//   - at close, any other failure (the connection dropped, the deadline, a
//     cancellation) may have come after the server received the end of the
//     data, so it wraps sluice.ErrOutcomeUnknown;
//   - a successful close is a delivered message, whatever follows.
func transact(c *smtp.Client, from string, rcpt []string, body io.Reader) error {
	var opts *smtp.MailOptions
	if !isASCII(from) || !allASCII(rcpt) {
		opts = &smtp.MailOptions{UTF8: true}
	}
	if err := c.Mail(from, opts); err != nil {
		return err
	}
	for _, addr := range rcpt {
		if err := c.Rcpt(addr, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			return err
		}
		return fmt.Errorf("%w: %w", sluice.ErrOutcomeUnknown, err)
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func allASCII(ss []string) bool {
	for _, s := range ss {
		if !isASCII(s) {
			return false
		}
	}
	return true
}
