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

// SenderStamp resolves per-sender rules (ADR 0031): most-specific rule (exact
// address beats domain) → inbox default → unknown. Banner stays inbox-level.
func TestSenderStamp(t *testing.T) {
	in := inboxcfg.Inbox{Trust: inboxcfg.Trust{
		Level:      inboxcfg.TrustLevelUntrusted, // inbox default for no-match
		BodyBanner: true,
		Rules: []inboxcfg.TrustRule{
			{From: "ops@example.com", Level: inboxcfg.TrustLevelTrusted, Note: "operator"},
			{FromDomain: "scanner.local", Level: inboxcfg.TrustLevelUntrusted, Note: "device"},
		},
	}}

	// Exact-address rule.
	s := in.SenderStamp("ops@example.com")
	assert.Equal(t, provenance.TrustTrusted, s.Trust)
	assert.Equal(t, "operator", s.Note)
	assert.True(t, s.Banner, "banner stays inbox-level")

	// Domain rule.
	s = in.SenderStamp("printer@scanner.local")
	assert.Equal(t, provenance.TrustUntrusted, s.Trust)
	assert.Equal(t, "device", s.Note)

	// No rule → inbox default (untrusted here), no rule note.
	s = in.SenderStamp("random@elsewhere.test")
	assert.Equal(t, provenance.TrustUntrusted, s.Trust)
	assert.Empty(t, s.Note)

	// No parseable From → inbox default.
	assert.Equal(t, provenance.TrustUntrusted, in.SenderStamp("").Trust)
}

// An exact-address rule wins over a domain rule for the same sender.
func TestSenderStamp_MostSpecificWins(t *testing.T) {
	in := inboxcfg.Inbox{Trust: inboxcfg.Trust{Rules: []inboxcfg.TrustRule{
		{FromDomain: "example.com", Level: inboxcfg.TrustLevelUntrusted},
		{From: "ceo@example.com", Level: inboxcfg.TrustLevelTrusted},
	}}}
	assert.Equal(t, provenance.TrustTrusted, in.SenderStamp("ceo@example.com").Trust, "address beats domain")
	assert.Equal(t, provenance.TrustUntrusted, in.SenderStamp("intern@example.com").Trust, "domain for the rest")
	assert.Equal(t, provenance.TrustUnknown, in.SenderStamp("x@other.test").Trust, "no match → unknown default")
}

// Matching is case-insensitive on both the rule and the sender.
func TestSenderStamp_CaseInsensitive(t *testing.T) {
	in := inboxcfg.Inbox{Trust: inboxcfg.Trust{Rules: []inboxcfg.TrustRule{
		{From: "Ops@Example.COM", Level: inboxcfg.TrustLevelTrusted},
	}}}
	assert.Equal(t, provenance.TrustTrusted, in.SenderStamp("ops@example.com").Trust)
}

func TestValidateRules(t *testing.T) {
	ok := func(rules ...inboxcfg.TrustRule) error {
		return inboxcfg.Validate([]inboxcfg.Inbox{{Name: "x", Trust: inboxcfg.Trust{Rules: rules}}})
	}
	assert.NoError(t, ok(inboxcfg.TrustRule{From: "a@b.com", Level: inboxcfg.TrustLevelTrusted}))
	assert.NoError(t, ok(inboxcfg.TrustRule{FromDomain: "b.com", Level: inboxcfg.TrustLevelUntrusted, Note: "ok"}))

	assert.Error(t, ok(inboxcfg.TrustRule{Level: inboxcfg.TrustLevelTrusted}), "no matcher")
	assert.Error(t, ok(inboxcfg.TrustRule{From: "a@b.com", FromDomain: "b.com", Level: inboxcfg.TrustLevelTrusted}), "both matchers")
	assert.Error(t, ok(inboxcfg.TrustRule{From: "a@b.com", Level: "bogus"}), "bad level")
	assert.Error(t, ok(inboxcfg.TrustRule{From: "a@b.com", Level: "unknown"}), "unknown is not a rule outcome")
	assert.Error(t, ok(inboxcfg.TrustRule{From: "a@b.com", Level: inboxcfg.TrustLevelTrusted, Note: "bad\r\nnote"}), "note control char")
	assert.Error(t, ok(
		inboxcfg.TrustRule{From: "A@b.com", Level: inboxcfg.TrustLevelTrusted},
		inboxcfg.TrustRule{From: "a@B.com", Level: inboxcfg.TrustLevelUntrusted}), "duplicate from (case-insensitive)")
	assert.Error(t, ok(
		inboxcfg.TrustRule{FromDomain: "b.com", Level: inboxcfg.TrustLevelTrusted},
		inboxcfg.TrustRule{FromDomain: "b.com", Level: inboxcfg.TrustLevelUntrusted}), "duplicate from_domain")
}
