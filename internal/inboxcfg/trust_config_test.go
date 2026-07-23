package inboxcfg_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
	"github.com/yaad-index/darbaan/internal/provenance"
)

// TrustHeaderValue maps the configured level to the stamped value; an omitted
// level is the fail-safe unknown (ADR 0030).
func TestTrustHeaderValue(t *testing.T) {
	assert.Equal(t, provenance.TrustTrusted,
		inboxcfg.Inbox{Trust: inboxcfg.Trust{Level: inboxcfg.TrustLevelTrusted}}.TrustHeaderValue())
	assert.Equal(t, provenance.TrustUntrusted,
		inboxcfg.Inbox{Trust: inboxcfg.Trust{Level: inboxcfg.TrustLevelUntrusted}}.TrustHeaderValue())
	assert.Equal(t, provenance.TrustUnknown,
		inboxcfg.Inbox{}.TrustHeaderValue(), "omitted trust block → unknown")
}

// The trust block parses off an inbox, level and note included.
func TestParseTrust(t *testing.T) {
	inboxes, err := inboxcfg.Parse([]byte(`
inboxes:
  - name: work
    trust:
      level: trusted
      note: check with the operator
      body_banner: true
`))
	require.NoError(t, err)
	require.Len(t, inboxes, 1)
	assert.Equal(t, inboxcfg.TrustLevelTrusted, inboxes[0].Trust.Level)
	assert.Equal(t, "check with the operator", inboxes[0].Trust.Note)
	assert.True(t, inboxes[0].Trust.BodyBanner)
	assert.Equal(t, provenance.TrustTrusted, inboxes[0].TrustHeaderValue())
}

// Validate rejects an unknown level and a note that isn't a single sane header
// value; the valid shapes pass (ADR 0030).
func TestValidateTrust(t *testing.T) {
	ok := func(tr inboxcfg.Trust) error {
		return inboxcfg.Validate([]inboxcfg.Inbox{{Name: "x", Trust: tr}})
	}

	assert.NoError(t, ok(inboxcfg.Trust{}), "omitted level is valid (→ unknown)")
	assert.NoError(t, ok(inboxcfg.Trust{Level: inboxcfg.TrustLevelTrusted}))
	assert.NoError(t, ok(inboxcfg.Trust{Level: inboxcfg.TrustLevelUntrusted, Note: "a plain note"}))

	assert.Error(t, ok(inboxcfg.Trust{Level: "bogus"}), "unknown level rejected")
	assert.Error(t, ok(inboxcfg.Trust{Note: strings.Repeat("x", 513)}), "over-long note rejected")
	assert.Error(t, ok(inboxcfg.Trust{Note: "inject\r\nX-Evil: 1"}), "CR/LF in note rejected (header injection)")
	assert.Error(t, ok(inboxcfg.Trust{Note: "tab\tinside"}), "control char in note rejected")
}
