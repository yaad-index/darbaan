// Package bounce generates MAILER-DAEMON-style DSN bounce messages for rejected
// outbound mail (ADR 0006). The bounce is an RFC 3464 multipart/report —
// human-readable text + message/delivery-status + the original attached as
// message/rfc822 — assembled with the go-message MIME library (ADR 0014). The
// rejection reason originates from the approver and never echoes attacker email
// text. Signing the bounce (ADR 0007) is a separate component (#26).
package bounce

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-message"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// Bounce is a generated DSN bounce, ready to deliver into the agent's mailbox.
type Bounce struct {
	Owner   string // the agent whose send was rejected (mailbox owner)
	From    string // MAILER-DAEMON@<domain>
	To      string // the original submitter
	Subject string
	Raw     []byte // the full RFC 3464 message/rfc822
}

const subject = "Undelivered Mail Returned to Sender"

// Generate builds the DSN bounce for a rejected message. retryable selects the
// DSN status: 4.7.1 (transient — revise and resubmit) vs 5.7.1 (permanent —
// message refused by policy). reason is the approver's reason; it is sanitized
// of CR/LF before embedding and never includes the original message body.
func Generate(orig sluice.Message, reason string, retryable bool, domain string) (Bounce, error) {
	if domain == "" {
		domain = "localhost"
	}
	reason = sanitize(reason)
	status, disposition := "5.7.1", "permanent"
	if retryable {
		status, disposition = "4.7.1", "transient"
	}
	from := "MAILER-DAEMON@" + domain
	to := orig.From // the bounce goes back to the original sender

	// Final-Recipient names the INTENDED recipient(s) — the addresses delivery
	// failed for (RFC 3464), not the sender. Fall back to the sender only if the
	// envelope had no recipients, so the DSN is never recipient-less.
	rcpts := orig.Rcpt
	if len(rcpts) == 0 {
		rcpts = []string{to}
	}

	var buf bytes.Buffer

	var top message.Header
	top.Set("From", from)
	top.Set("To", to)
	top.Set("Subject", subject)
	top.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	top.Set("Auto-Submitted", "auto-replied")
	top.SetContentType("multipart/report", map[string]string{"report-type": "delivery-status"})

	mw, err := message.CreateWriter(&buf, top)
	if err != nil {
		return Bounce{}, fmt.Errorf("bounce: create writer: %w", err)
	}

	if err := writeText(mw, domain, reason, disposition, status, retryable); err != nil {
		return Bounce{}, err
	}
	if err := writeDeliveryStatus(mw, domain, rcpts, status, reason); err != nil {
		return Bounce{}, err
	}
	if err := writeOriginal(mw, orig.Raw); err != nil {
		return Bounce{}, err
	}
	if err := mw.Close(); err != nil {
		return Bounce{}, fmt.Errorf("bounce: close: %w", err)
	}

	return Bounce{Owner: orig.Agent, From: from, To: to, Subject: subject, Raw: buf.Bytes()}, nil
}

func writeText(mw *message.Writer, domain, reason, disposition, status string, retryable bool) error {
	var h message.Header
	h.SetContentType("text/plain", map[string]string{"charset": "utf-8"})
	pw, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("bounce: text part: %w", err)
	}
	advice := "Do not retry."
	if retryable {
		advice = "You may revise the message and resubmit it."
	}
	body := fmt.Sprintf(
		"This is the Darbaan mail gate at %s.\r\n\r\n"+
			"Your message was not delivered. It was refused by policy (%s).\r\n\r\n"+
			"Reason: %s\r\n\r\n"+
			"Delivery status: %s.\r\n%s\r\n",
		domain, status, reason, disposition, advice)
	if _, err := pw.Write([]byte(body)); err != nil {
		return fmt.Errorf("bounce: write text: %w", err)
	}
	return pw.Close()
}

func writeDeliveryStatus(mw *message.Writer, domain string, rcpts []string, status, reason string) error {
	var h message.Header
	h.SetContentType("message/delivery-status", nil)
	pw, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("bounce: delivery-status part: %w", err)
	}
	// Per-message fields, then one per-recipient group for each INTENDED
	// recipient — the address delivery failed for, not the bounce recipient
	// (RFC 3464). Recipients are CR/LF-sanitized against header injection.
	var b strings.Builder
	fmt.Fprintf(&b, "Reporting-MTA: dns; %s\r\n", domain)
	for _, rcpt := range rcpts {
		fmt.Fprintf(&b,
			"\r\nFinal-Recipient: rfc822; %s\r\n"+
				"Action: failed\r\n"+
				"Status: %s\r\n"+
				"Diagnostic-Code: X-Darbaan; %s\r\n",
			sanitize(rcpt), status, reason)
	}
	if _, err := pw.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("bounce: write delivery-status: %w", err)
	}
	return pw.Close()
}

func writeOriginal(mw *message.Writer, raw []byte) error {
	var h message.Header
	h.SetContentType("message/rfc822", nil)
	pw, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("bounce: original part: %w", err)
	}
	if _, err := pw.Write(raw); err != nil {
		return fmt.Errorf("bounce: write original: %w", err)
	}
	return pw.Close()
}

// sanitize strips CR/LF so an approver-supplied reason cannot inject header
// lines into the DSN part.
func sanitize(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
