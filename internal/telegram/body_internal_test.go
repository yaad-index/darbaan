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
	m := sluice.Meta{ID: "7", From: "a@x", Rcpt: []string{"b@y"}, Subject: "s", Size: 10}

	out := formatNotification(m, "the message body")
	assert.Contains(t, out, "subject: s")
	assert.Contains(t, out, "--- body ---")
	assert.Contains(t, out, "the message body")

	assert.Contains(t, formatNotification(m, ""), "(no text body)")
}

func TestFormatNotificationTruncates(t *testing.T) {
	m := sluice.Meta{ID: "7", Subject: "s"}
	big := strings.Repeat("x", 8000)
	out := formatNotification(m, big)
	assert.LessOrEqual(t, len([]rune(out)), maxNotificationRunes)
	assert.Contains(t, out, "...(truncated, 8000 bytes)")
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
