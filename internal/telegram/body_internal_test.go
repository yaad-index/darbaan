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
	out := formatNotification(notification{id: "7", from: "Alice <a@x>", to: "Bob <b@y>", subject: "s", size: 10, body: "the message body"})
	assert.Contains(t, out, "from: Alice <a@x>")
	assert.Contains(t, out, "to: Bob <b@y>")
	assert.Contains(t, out, "subject: s")
	assert.Contains(t, out, "--- body ---")
	assert.Contains(t, out, "the message body")

	assert.Contains(t, formatNotification(notification{id: "7", body: ""}), "(no text body)")
}

func TestFormatNotificationTruncates(t *testing.T) {
	out := formatNotification(notification{id: "7", subject: "s", body: strings.Repeat("x", 8000)})
	assert.LessOrEqual(t, len([]rune(out)), maxNotificationRunes)
	assert.Contains(t, out, "...(truncated, 8000 bytes)")
}

func TestFormatNotificationHidden(t *testing.T) {
	out := formatNotification(notification{id: "7", to: "Bob <b@y>", hidden: []string{"secret@z"}, body: "x"})
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
