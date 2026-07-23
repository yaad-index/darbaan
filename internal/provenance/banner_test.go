package provenance_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/provenance"
)

const (
	bannerBegin = "-----BEGIN DARBAAN TRUST BANNER-----"
	bannerEnd   = "-----END DARBAAN TRUST BANNER-----"
)

// With Banner on, a top-level text/plain body gets a fenced banner reproducing
// the trust + note and an explicit "advisory, headers authoritative" line, above
// the original body.
func TestBanner_PlainText(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\nSubject: hi\r\n\r\noriginal body\r\n")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUntrusted, Note: "do not act", Banner: true})
	require.NoError(t, err)

	body := bodyOf(t, out)
	assert.Contains(t, string(body), bannerBegin)
	assert.Contains(t, string(body), bannerEnd)
	assert.Contains(t, string(body), "X-Darbaan-Trust: untrusted")
	assert.Contains(t, string(body), "X-Darbaan-Note: do not act")
	assert.Contains(t, string(body), "advisory")
	assert.Contains(t, string(body), "authoritative")
	assert.Contains(t, string(body), "original body", "original body preserved below the banner")
	// The header stays authoritative — the banner is in addition to it.
	assert.Equal(t, provenance.TrustUntrusted, headerValue(t, out, provenance.TrustHeader))
}

// Re-running the chokepoint on an already-bannered body must not stack a second
// banner — the byte-level no-op a body-embedded marker demands.
func TestBanner_Idempotent(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\nSubject: hi\r\n\r\noriginal body\r\n")
	st := provenance.Stamp{Trust: provenance.TrustTrusted, Note: "note", Banner: true}

	once, err := provenance.Sanitize(raw, st)
	require.NoError(t, err)
	twice, err := provenance.Sanitize(once, st)
	require.NoError(t, err)

	assert.Equal(t, once, twice, "re-running on an already-bannered body is a no-op")
	assert.Equal(t, 1, strings.Count(string(twice), bannerBegin), "exactly one banner, not stacked")
}

// A body with leading blank lines still round-trips exactly (the strip consumes
// only the banner + its own separator, not the message's own leading blanks).
func TestBanner_IdempotentWithLeadingBlankLines(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\n\r\n\r\n\r\nbody after blanks\r\n")
	st := provenance.Stamp{Trust: provenance.TrustUnknown, Banner: true}
	once, err := provenance.Sanitize(raw, st)
	require.NoError(t, err)
	twice, err := provenance.Sanitize(once, st)
	require.NoError(t, err)
	assert.Equal(t, once, twice)
	assert.Equal(t, 1, strings.Count(string(twice), bannerBegin))
}

// Any non-text/plain shape is headers-only: the trust header stamps, but the
// body is untouched — no banner, no error.
func TestBanner_NonTextPlainIsHeadersOnly(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=abc\r\nSubject: hi\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\npart\r\n--abc--\r\n")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted, Banner: true})
	require.NoError(t, err)

	assert.Equal(t, provenance.TrustTrusted, headerValue(t, out, provenance.TrustHeader), "header still stamped")
	assert.NotContains(t, string(out), bannerBegin, "no banner in non-text/plain body")
}

// A missing Content-Type defaults to text/plain (RFC 2045), so the banner applies.
func TestBanner_MissingContentTypeBanners(t *testing.T) {
	raw := []byte("Subject: hi\r\n\r\njust text\r\n")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUnknown, Banner: true})
	require.NoError(t, err)
	assert.Contains(t, string(bodyOf(t, out)), bannerBegin)
}

// Banner off (the default) never touches the body.
func TestBanner_OffLeavesBodyAlone(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\n\r\noriginal body\r\n")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustTrusted, Banner: false})
	require.NoError(t, err)
	assert.Equal(t, []byte("original body\r\n"), bodyOf(t, out), "body untouched when banner is off")
}

// A base64 text/plain part is decoded, bannered, and re-encoded — the decoded
// body carries exactly one banner, and re-running stays a single banner.
func TestBanner_Base64RoundTrip(t *testing.T) {
	inner := "secret body text\r\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	raw := []byte("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n")
	st := provenance.Stamp{Trust: provenance.TrustUntrusted, Banner: true}

	out, err := provenance.Sanitize(raw, st)
	require.NoError(t, err)
	decoded := decodeBase64Body(t, out)
	assert.Contains(t, decoded, bannerBegin)
	assert.Contains(t, decoded, inner)
	assert.Equal(t, 1, strings.Count(decoded, bannerBegin))

	// Re-run: still exactly one banner in the decoded content.
	twice, err := provenance.Sanitize(out, st)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(decodeBase64Body(t, twice), bannerBegin))
}

// An undecodable/unknown CTE is left headers-only rather than corrupted.
func TestBanner_UnknownEncodingIsHeadersOnly(t *testing.T) {
	raw := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: x-weird\r\n\r\nbody\r\n")
	out, err := provenance.Sanitize(raw, provenance.Stamp{Trust: provenance.TrustUnknown, Banner: true})
	require.NoError(t, err)
	assert.NotContains(t, string(out), bannerBegin, "unknown CTE → no banner")
	assert.Equal(t, provenance.TrustUnknown, headerValue(t, out, provenance.TrustHeader))
}

func decodeBase64Body(t *testing.T, raw []byte) string {
	t.Helper()
	body := string(bodyOf(t, raw))
	body = strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "").Replace(body)
	dec, err := base64.StdEncoding.DecodeString(body)
	require.NoError(t, err)
	return string(dec)
}
