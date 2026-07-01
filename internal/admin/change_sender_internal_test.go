package admin

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewriteFrom replaces the From header and leaves every other header + the body
// untouched.
func TestRewriteFrom(t *testing.T) {
	raw := []byte("From: assistant@x.test\r\nTo: d@y.test\r\nSubject: hi\r\n\r\nbody line 1\r\nbody line 2\r\n")
	out, err := rewriteFrom(raw, "personal@y.test")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "From: personal@y.test")
	assert.NotContains(t, s, "assistant@x.test")
	assert.Contains(t, s, "Subject: hi")
	assert.Contains(t, s, "body line 1\r\nbody line 2\r\n")
}

// The MIME body is preserved byte-for-byte (ADR 0025): only the top-level From
// header changes; the multipart body — including a "From " line inside it — is
// unchanged.
func TestRewriteFromPreservesBody(t *testing.T) {
	body := "--b\r\nContent-Type: text/plain\r\n\r\nreply; a From: line inside the body must stay\r\n--b--\r\n"
	raw := []byte("From: assistant@x.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" + body)

	out, err := rewriteFrom(raw, "personal@y.test")
	require.NoError(t, err)

	_, gotBody, found := strings.Cut(string(out), "\r\n\r\n")
	require.True(t, found)
	assert.Equal(t, body, gotBody, "body preserved byte-for-byte")
	assert.Contains(t, string(out), "From: personal@y.test")
	assert.NotContains(t, string(out), "assistant@x.test")
}
