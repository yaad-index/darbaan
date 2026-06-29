package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func TestBodyTextPlain(t *testing.T) {
	raw := []byte("Subject: hi\r\nContent-Type: text/plain\r\n\r\nhello body\r\n")
	assert.Equal(t, "hello body", bodyText(raw))
}

func TestBodyTextMultipartPrefersPlain(t *testing.T) {
	raw := []byte("Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/html\r\n\r\n<p>nope</p>\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nthe plain part\r\n" +
		"--b--\r\n")
	assert.Equal(t, "the plain part", bodyText(raw))
}

func TestBodyTextQuotedPrintableDecoded(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9 time\r\n")
	assert.Equal(t, "café time", bodyText(raw))
}

func TestBodyTextNoTextPart(t *testing.T) {
	raw := []byte("Content-Type: application/octet-stream\r\n\r\n\x00\x01\x02")
	assert.Equal(t, "", bodyText(raw))
	assert.Equal(t, "", bodyText(nil))
}

func TestFormatNotificationBody(t *testing.T) {
	out, offloaded := formatNotification(notification{id: "7", from: "Alice <a@x>", to: "Bob <b@y>", subject: "s", size: 10, body: "the message body"})
	assert.False(t, offloaded) // short body fits inline
	assert.Contains(t, out, "from: Alice <a@x>")
	assert.Contains(t, out, "to: Bob <b@y>")
	assert.Contains(t, out, "subject: s")
	assert.Contains(t, out, "--- body ---")
	assert.Contains(t, out, "the message body")

	empty, _ := formatNotification(notification{id: "7", body: ""})
	assert.Contains(t, empty, "(no text body)")
}

func TestFormatNotificationTruncates(t *testing.T) {
	out, offloaded := formatNotification(notification{id: "7", subject: "s", body: strings.Repeat("x", 8000)})
	assert.True(t, offloaded) // long body offloaded to a .txt attachment
	assert.LessOrEqual(t, len([]rune(out)), maxNotificationRunes)
	assert.Contains(t, out, "full body attached as full-message-body.txt")
}

func TestFormatNotificationHidden(t *testing.T) {
	out, _ := formatNotification(notification{id: "7", to: "Bob <b@y>", hidden: []string{"secret@z"}, body: "x"})
	assert.Contains(t, out, "(!) also delivering to (not in headers): secret@z")
}

func TestHeaderAddrs(t *testing.T) {
	raw := []byte("From: Alice <a@x.test>\r\nTo: Bob <b@y.test>\r\nCc: c@z.test\r\nSubject: s\r\n\r\nbody")
	from, to, set, parsed := headerAddrs(raw)
	assert.True(t, parsed)
	assert.Equal(t, "Alice <a@x.test>", from)
	assert.Equal(t, "Bob <b@y.test>, c@z.test", to)
	assert.True(t, set["b@y.test"] && set["c@z.test"])

	_, _, _, parsed = headerAddrs(nil)
	assert.False(t, parsed) // no false-flagging when unparseable
}

func TestHiddenRcpts(t *testing.T) {
	set := map[string]bool{"b@y.test": true}
	// secret@z is in the envelope but not the headers — a Bcc the operator must see.
	assert.Equal(t, []string{"secret@z.test"}, hiddenRcpts([]string{"b@y.test", "secret@z.test"}, set))
	assert.Empty(t, hiddenRcpts([]string{"b@y.test"}, set))
}

func TestAttachments(t *testing.T) {
	// multipart/mixed: a text body + a base64 PDF attachment ("aGVsbG8=" = "hello").
	raw := []byte("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nthe body\r\n" +
		"--b\r\nContent-Type: application/pdf; name=\"doc.pdf\"\r\n" +
		"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n" +
		"--b--\r\n")
	atts := attachments(raw)
	require.Len(t, atts, 1)
	assert.Equal(t, "doc.pdf", atts[0].filename)
	assert.Equal(t, "application/pdf", atts[0].contentType)
	assert.Equal(t, []byte("hello"), atts[0].data) // transfer-decoded
	assert.Equal(t, int64(5), atts[0].size)
}

func TestAttachmentsNonTextLeafAndNone(t *testing.T) {
	// A non-text leaf with no disposition is still an attachment (unnamed).
	img := []byte("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n" +
		"--b\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--b--\r\n")
	atts := attachments(img)
	require.Len(t, atts, 1)
	assert.Equal(t, "(unnamed)", atts[0].filename)
	assert.Equal(t, "image/png", atts[0].contentType)

	// text/plain + text/html alternative is the body only — no attachments.
	none := []byte("Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--b--\r\n")
	assert.Empty(t, attachments(none))
}

func TestAttachmentCaption(t *testing.T) {
	assert.Equal(t, "msg 18 - invoice.pdf", attachmentCaption("18", "invoice.pdf"))
}

func TestFullBodyCaption(t *testing.T) {
	// The caption is the trust anchor (ADR 0025): it names the message id and
	// states explicitly that this is NOT a file the email carried.
	caption := fullBodyCaption("18")
	assert.Contains(t, caption, "msg 18")
	assert.Contains(t, caption, "FULL MESSAGE BODY")
	assert.Contains(t, caption, "NOT a file the email carried")
}

func TestHumanSize(t *testing.T) {
	assert.Equal(t, "512 B", humanSize(512))
	assert.Equal(t, "1 KB", humanSize(1024))
	assert.Equal(t, "1.5 KB", humanSize(1536))
	assert.Equal(t, "2 MB", humanSize(2*1024*1024))
}

func TestAttachmentsLine(t *testing.T) {
	assert.Equal(t, "attachments: none", attachmentsLine(nil))
	assert.Contains(t,
		attachmentsLine([]attachment{{filename: "a.pdf", contentType: "application/pdf", size: 204 * 1024}}),
		"a.pdf (application/pdf, 204 KB)")
	assert.Contains(t,
		attachmentsLine([]attachment{{filename: "big.zip", contentType: "application/zip", size: 60 * 1024 * 1024}}),
		"too large to preview")
}

func TestFormatNotificationAttachmentsSurviveTruncation(t *testing.T) {
	n := notification{
		id: "7", subject: "s", body: strings.Repeat("x", 8000),
		attachments: []attachment{{filename: "secret.pdf", contentType: "application/pdf", size: 1024}},
	}
	out, offloaded := formatNotification(n)
	assert.True(t, offloaded)
	assert.LessOrEqual(t, len([]rune(out)), maxNotificationRunes)
	assert.Contains(t, out, "secret.pdf")        // attachment list survives a long-body truncation
	assert.Contains(t, out, "[truncated — full") // ...because the body offloaded instead
}

func TestPrunePosted(t *testing.T) {
	c, err := New("123:fake", 999, 0, admin.NewClient("127.0.0.1:1", "t"))
	require.NoError(t, err)
	c.posted = map[string]bool{"a": true, "b": true, "c": true}

	// a still pending; b decided; c gone from the queue.
	c.prunePosted([]sluice.Meta{
		{ID: "a", Status: sluice.StatusPending},
		{ID: "b", Status: sluice.StatusApproved},
	})
	assert.Equal(t, map[string]bool{"a": true}, c.posted)
}

func TestPrunePendingTTL(t *testing.T) {
	c, err := New("123:fake", 999, 0, admin.NewClient("127.0.0.1:1", "t"))
	require.NoError(t, err)
	now := time.Now()
	c.pending = map[int]rejectState{
		1: {id: "x", at: now.Add(-2 * time.Hour)},   // stale
		2: {id: "y", at: now.Add(-1 * time.Minute)}, // fresh
	}
	c.prunePendingLocked(now)
	_, hasStale := c.pending[1]
	_, hasFresh := c.pending[2]
	assert.False(t, hasStale)
	assert.True(t, hasFresh)
}
