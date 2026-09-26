package inboxcfg

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/provenance"
)

// msg joins header lines into a raw message with a short body.
func msg(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\nbody\r\n")
}

const (
	// The order the upstream's own fields take on real mail (#237, A1): its internal
	// hops, its inbound hop, then its results, then the sender's own hop.
	upInternal = "Received: by 2002:a05:6000::1 with SMTP id x; Sat, 26 Sep 2026 10:00:02 +0000"
	upInbound  = "Received: from out.sender.test (out.sender.test [192.0.2.1]) by mx.example with ESMTPS id y; Sat, 26 Sep 2026 10:00:01 +0000"
	upSPF      = "Received-SPF: pass (mx.example: domain of a@sender.test designates 192.0.2.1 as permitted sender)"
	senderHop  = "Received: by out.sender.test with SMTP id z; Sat, 26 Sep 2026 10:00:00 +0000"
	from       = "From: A <a@sender.test>"
)

func ar(id, results string) string { return "Authentication-Results: " + id + "; " + results }

func TestAuthenticated(t *testing.T) {
	dmarcPass := ar("mx.example", "dkim=pass header.d=sender.test; dmarc=pass header.from=sender.test")
	dmarcFail := ar("mx.example", "dkim=fail header.d=sender.test; dmarc=fail header.from=sender.test")
	cases := []struct {
		name string
		raw  []byte
		want bool
	}{
		{"real order: results below the upstream's inbound hop", msg(upInternal, upInbound, upSPF, dmarcPass, senderHop, from), true},
		{"results above every Received", msg(dmarcPass, upInbound, senderHop, from), true},
		{"no Received below the run", msg(upInbound, dmarcPass, from), true},
		{"upstream says fail", msg(upInbound, dmarcFail, senderHop, from), false},
		{"forged pass below the sender's hop is ignored", msg(upInbound, dmarcFail, senderHop, dmarcPass, from), false},
		{"a fail below the sender's hop is ignored", msg(upInbound, dmarcPass, senderHop, dmarcFail, from), true},
		// The stated prerequisite, pinned: with no field from the upstream, the
		// topmost one bearing its identity is the sender's, and the gate reads it.
		{"no field from the upstream: a sender's is read", msg(upInbound, senderHop, dmarcPass, from), true},
		{"forged pass directly under the upstream's fail: disagreement fails closed", msg(upInbound, dmarcFail, dmarcPass, senderHop, from), false},
		{"forged fail directly under the upstream's pass refuses", msg(upInbound, dmarcPass, dmarcFail, senderHop, from), false},
		{"another authserv-id is ignored", msg(upInbound, ar("mx.other", "dmarc=pass header.from=sender.test"), senderHop, from), false},
		{"another authserv-id passing beside the upstream's fail", msg(upInbound, dmarcFail, ar("mx.other", "dmarc=pass header.from=sender.test"), senderHop, from), false},
		{"authserv-id matches case-insensitively", msg(upInbound, ar("MX.Example", "dmarc=pass header.from=sender.test"), senderHop, from), true},
		{"no results at all", msg(upInbound, senderHop, from), false},
		{"dmarc pass for another domain", msg(upInbound, ar("mx.example", "dmarc=pass header.from=evil.test"), senderHop, from), false},
		{"aligned dkim pass with no dmarc result", msg(upInbound, ar("mx.example", "dkim=pass header.d=sender.test"), senderHop, from), true},
		{"aligned dkim fail", msg(upInbound, ar("mx.example", "dkim=fail header.d=sender.test"), senderHop, from), false},
		{"dkim pass for another domain", msg(upInbound, ar("mx.example", "dkim=pass header.d=evil.test"), senderHop, from), false},
		{"aligned dkim pass does not override a dmarc fail", msg(upInbound, ar("mx.example", "dkim=pass header.d=sender.test; dmarc=fail header.from=sender.test"), senderHop, from), false},
		{"an unparseable Authentication-Results fails closed", msg(upInbound, "Authentication-Results: mx.example; dmarc", dmarcPass, senderHop, from), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, authenticated(c.raw, "mx.example", "sender.test"))
		})
	}
	assert.False(t, authenticated(msg(upInbound, ar("", "dmarc=pass header.from=sender.test"), from), "", "sender.test"),
		"no identity, no trust, even beside a field with an empty identity")
	assert.False(t, authenticated(msg(upInbound, dmarcPass, from), "mx.example", ""), "no From domain, no trust")
}

// Stamp gates only the trusted outcome; the note goes with it.
func TestInboxStampGatesTrusted(t *testing.T) {
	in := Inbox{Trust: Trust{
		Level: TrustLevelUntrusted, RequireAuthenticated: true, AuthservID: "mx.example",
		Rules: []TrustRule{{From: "a@sender.test", Level: TrustLevelTrusted, Note: "operator address"}},
	}}
	pass := msg(upInbound, ar("mx.example", "dmarc=pass header.from=sender.test"), senderHop, from)
	fail := msg(upInbound, ar("mx.example", "dmarc=fail header.from=sender.test"), senderHop, from)

	got := in.Stamp(pass)
	assert.Equal(t, provenance.TrustTrusted, got.Trust)
	assert.Equal(t, "operator address", got.Note)

	got = in.Stamp(fail)
	assert.Equal(t, provenance.TrustUnknown, got.Trust, "a failed gate never yields trusted")
	assert.Empty(t, got.Note, "the note belongs to the trusted outcome")

	other := msg(upInbound, ar("mx.example", "dmarc=fail header.from=else.test"), senderHop, "From: b@else.test")
	assert.Equal(t, provenance.TrustUntrusted, in.Stamp(other).Trust, "untrusted is not the gate's to change")

	in.Trust.RequireAuthenticated = false
	assert.Equal(t, provenance.TrustTrusted, in.Stamp(fail).Trust, "gate off: the rule applies as before")
}
