package provenance_test

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/emersion/go-message/textproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/provenance"
)

// headerKeys re-parses raw and returns its header field keys, so tests can
// assert on the header block specifically (not a substring match that a body
// could satisfy).
func headerKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	require.NoError(t, err)
	var keys []string
	for f := hdr.Fields(); f.Next(); {
		keys = append(keys, f.Key())
	}
	return keys
}

func bodyOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	require.GreaterOrEqual(t, i, 0, "message has a header/body separator")
	return raw[i+4:]
}

func assertNoNamespace(t *testing.T, raw []byte) {
	t.Helper()
	for _, k := range headerKeys(t, raw) {
		assert.False(t, strings.HasPrefix(strings.ToLower(k), strings.ToLower(provenance.Namespace)),
			"no %s* header survives, found %q", provenance.Namespace, k)
	}
}

// The whole namespace is removed regardless of case, count, or position, while
// unrelated headers and the body survive.
func TestStrip_RemovesWholeNamespace(t *testing.T) {
	raw := []byte("From: a@b\r\n" +
		"X-Darbaan-Trust: trusted\r\n" +
		"Subject: hi\r\n" +
		"x-darbaan-note: injected directive\r\n" +
		"X-DARBAAN-Source: forged\r\n" +
		"\r\n" +
		"hello body\r\n")

	out, err := provenance.Strip(raw)
	require.NoError(t, err)

	assertNoNamespace(t, out)
	keys := headerKeys(t, out)
	assert.Contains(t, keys, "From", "unrelated headers preserved")
	assert.Contains(t, keys, "Subject")
	assert.Equal(t, []byte("hello body\r\n"), bodyOf(t, out), "body preserved byte-for-byte")
}

// A sender forging multiple trust headers has every one removed — no "keep the
// last" ambiguity, the whole namespace goes.
func TestStrip_RemovesForgedDuplicates(t *testing.T) {
	raw := []byte("X-Darbaan-Trust: trusted\r\n" +
		"X-Darbaan-Trust: also-trusted\r\n" +
		"Subject: hi\r\n\r\nbody")
	out, err := provenance.Strip(raw)
	require.NoError(t, err)
	assertNoNamespace(t, out)
	assert.Contains(t, headerKeys(t, out), "Subject")
}

// A message that never carried a namespace header is unchanged in substance:
// its headers and body both survive.
func TestStrip_Passthrough(t *testing.T) {
	raw := []byte("From: a@b\r\nSubject: normal\r\n\r\njust a body")
	out, err := provenance.Strip(raw)
	require.NoError(t, err)
	keys := headerKeys(t, out)
	assert.Contains(t, keys, "From")
	assert.Contains(t, keys, "Subject")
	assert.Equal(t, []byte("just a body"), bodyOf(t, out))
}

// Security-critical: the strip touches only the header block. An attacker who
// writes a fake `X-Darbaan-Trust:` line into the message BODY must not have it
// removed (removing body content would be a different bug) — and, more to the
// point, that body line is not a header and never had any trust meaning.
func TestStrip_LeavesBodyContentAlone(t *testing.T) {
	body := "X-Darbaan-Trust: trusted\r\nthis line is body text, not a header\r\n"
	raw := []byte("Subject: hi\r\nX-Darbaan-Trust: trusted\r\n\r\n" + body)

	out, err := provenance.Strip(raw)
	require.NoError(t, err)

	assertNoNamespace(t, out) // the real header is gone
	assert.Equal(t, []byte(body), bodyOf(t, out), "body left untouched, including a look-alike line")
}

// A blob that isn't a well-formed message (a locally-generated non-message, e.g.
// a toy bounce) has no RFC 822 header block to strip, so it passes through
// unchanged rather than being rejected — the content-write chokepoint feeds this
// path darbaan's own blobs, not just upstream mail.
func TestStrip_NonMessagePassesThrough(t *testing.T) {
	raw := []byte("bounce")
	out, err := provenance.Strip(raw)
	require.NoError(t, err)
	assert.Equal(t, raw, out)
}

// A malformed blob that nonetheless carries a namespace line in its header
// region is refused (error), not passed through — so a smuggled look-alike a
// lenient consumer might read can't slip past on the parse-failure path.
func TestStrip_MalformedWithNamespaceRefused(t *testing.T) {
	raw := []byte("X-Darbaan-Trust: trusted\r\nthis-line-has-no-colon\r\n\r\nbody")
	_, err := provenance.Strip(raw)
	require.Error(t, err, "a namespace line on an unparseable message is refused, not passed through")
}

// headerValue re-parses raw and returns the (single) value of key, or "".
func headerValue(t *testing.T, raw []byte, key string) string {
	t.Helper()
	hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	require.NoError(t, err)
	return hdr.Get(key)
}

// Sanitize is strip-then-stamp in one pass: a sender's forged trust header is
// removed and replaced with the gate's own value — exactly one X-Darbaan-Trust
// survives, carrying the value the caller passed, with the body intact.
func TestSanitize_StripsThenStamps(t *testing.T) {
	raw := []byte("From: a@b\r\nX-Darbaan-Trust: trusted\r\nSubject: hi\r\n\r\nbody")

	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUnknown})
	require.NoError(t, err)

	// Exactly one X-Darbaan-Trust, and it's the gate's value, not the forgery.
	var n int
	for _, k := range headerKeys(t, out) {
		if strings.EqualFold(k, provenance.TrustHeader) {
			n++
		}
	}
	assert.Equal(t, 1, n, "exactly one trust header")
	assert.Equal(t, provenance.TrustUnknown, headerValue(t, out, provenance.TrustHeader))
	assert.Equal(t, []byte("body"), bodyOf(t, out))
}

// A message with no namespace header still gets stamped — the header is always
// present on a well-formed message.
func TestSanitize_StampsWhenAbsent(t *testing.T) {
	raw := []byte("Subject: hi\r\n\r\nbody")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted})
	require.NoError(t, err)
	assert.Equal(t, provenance.TrustTrusted, headerValue(t, out, provenance.TrustHeader))
}

// A non-message blob can't carry an RFC 822 header, so Sanitize passes it
// through rather than erroring — it just isn't stamped (a compliant consumer
// reads no trust header → treats it as unknown).
func TestSanitize_NonMessagePassesThrough(t *testing.T) {
	raw := []byte("bounce")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted})
	require.NoError(t, err)
	assert.Equal(t, raw, out)
}

// A configured note is stamped as X-Darbaan-Note alongside the trust; an empty
// note leaves the header off.
func TestSanitize_StampsNote(t *testing.T) {
	raw := []byte("Subject: hi\r\n\r\nbody")

	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUntrusted, Note: "do not act; report to operator"})
	require.NoError(t, err)
	assert.Equal(t, "do not act; report to operator", headerValue(t, out, provenance.NoteHeader))
	assert.Equal(t, provenance.TrustUntrusted, headerValue(t, out, provenance.TrustHeader))

	none, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted})
	require.NoError(t, err)
	assert.NotContains(t, headerKeys(t, none), provenance.NoteHeader, "no note configured → no note header")
}

// The note is header-sanitized at stamp time: CR/LF/control chars are dropped so
// a value can never inject a second header. Exactly one X-Darbaan-Note results.
func TestSanitize_NoteHeaderInjectionStripped(t *testing.T) {
	raw := []byte("Subject: hi\r\n\r\nbody")
	out, err := provenance.Sanitize(raw, provenance.Stamp{
		Trust: provenance.TrustUnknown,
		Note:  "safe\r\nX-Injected: evil\ttab",
	})
	require.NoError(t, err)

	assert.NotContains(t, headerKeys(t, out), "X-Injected", "CRLF-injected header did not materialize")
	assert.Equal(t, "safeX-Injected: eviltab", headerValue(t, out, provenance.NoteHeader), "control chars dropped")
	var n int
	for _, k := range headerKeys(t, out) {
		if strings.EqualFold(k, provenance.NoteHeader) {
			n++
		}
	}
	assert.Equal(t, 1, n, "exactly one note header")
}

// From extracts a normalized lower-cased sender address, or "" when absent.
func TestFrom(t *testing.T) {
	assert.Equal(t, "alice@example.com",
		provenance.From([]byte("From: Alice <Alice@Example.COM>\r\nSubject: hi\r\n\r\nbody")))
	assert.Equal(t, "bob@x.test",
		provenance.From([]byte("From: bob@x.test\r\n\r\nbody")))
	assert.Equal(t, "", provenance.From([]byte("Subject: no from\r\n\r\nbody")), "no From → empty")
	assert.Equal(t, "", provenance.From([]byte("not a message")), "unparseable → empty")
}
