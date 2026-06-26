package bounce_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/emersion/go-message"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/bounce"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// parseParts parses the bounce and returns each part's body keyed by content type.
func parseParts(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	ent, err := message.Read(bytes.NewReader(raw))
	require.NoError(t, err)
	mr := ent.MultipartReader()
	require.NotNil(t, mr, "bounce must be multipart")

	parts := map[string]string{}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		ct, _, _ := p.Header.ContentType()
		body, err := io.ReadAll(p.Body)
		require.NoError(t, err)
		parts[ct] = string(body)
	}
	return parts
}

func TestGeneratePermanent(t *testing.T) {
	orig := sluice.Message{Agent: "agent", From: "sender@local", Raw: []byte("Subject: hi\r\n\r\nbody-marker\r\n")}
	b, err := bounce.Generate(orig, "refused by policy", false, "darbaan.test")
	require.NoError(t, err)

	assert.Equal(t, "agent", b.Owner)
	assert.Equal(t, "MAILER-DAEMON@darbaan.test", b.From)
	assert.Equal(t, "sender@local", b.To)

	parts := parseParts(t, b.Raw)
	require.Contains(t, parts, "text/plain")
	require.Contains(t, parts, "message/delivery-status")
	require.Contains(t, parts, "message/rfc822")

	assert.Contains(t, parts["text/plain"], "refused by policy")
	assert.Contains(t, parts["message/delivery-status"], "Status: 5.7.1")
	assert.Contains(t, parts["message/delivery-status"], "Action: failed")
	assert.Contains(t, parts["message/rfc822"], "body-marker") // original attached intact
}

func TestGenerateTransient(t *testing.T) {
	orig := sluice.Message{Agent: "agent", From: "s@local", Raw: []byte("x")}
	b, err := bounce.Generate(orig, "revise and resubmit", true, "darbaan.test")
	require.NoError(t, err)

	parts := parseParts(t, b.Raw)
	assert.Contains(t, parts["message/delivery-status"], "Status: 4.7.1")
}

func TestReasonSanitizedAgainstHeaderInjection(t *testing.T) {
	orig := sluice.Message{Agent: "a", From: "s@local", Raw: []byte("x")}
	b, err := bounce.Generate(orig, "blocked\r\nInjected: evil", false, "darbaan.test")
	require.NoError(t, err)

	parts := parseParts(t, b.Raw)
	// CR/LF stripped: the reason cannot become its own header line in the DSN.
	assert.NotContains(t, parts["message/delivery-status"], "\nInjected:")
	assert.Contains(t, parts["message/delivery-status"], "blocked")
}

func TestDefaultDomain(t *testing.T) {
	b, err := bounce.Generate(sluice.Message{From: "s@local"}, "no", false, "")
	require.NoError(t, err)
	assert.Equal(t, "MAILER-DAEMON@localhost", b.From)
}
