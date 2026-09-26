package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
	"github.com/yaad-index/darbaan/internal/provenance"
)

// The resolver every write and serve path uses applies the inbox's
// Authentication-Results gate, not only its sender rules (ADR 0031 slice 2).
func TestProvenanceResolverAppliesAuthGate(t *testing.T) {
	resolve := provenanceResolver([]inboxcfg.Inbox{{
		Name: "work",
		Trust: inboxcfg.Trust{
			RequireAuthenticated: true, AuthservID: "mx.example",
			Rules: []inboxcfg.TrustRule{{From: "a@sender.test", Level: inboxcfg.TrustLevelTrusted}},
		},
	}})
	raw := func(results string) []byte {
		return []byte("Received: from out.sender.test by mx.example; Sat, 26 Sep 2026 10:00:01 +0000\r\n" +
			"Authentication-Results: mx.example; " + results + "\r\n" +
			"Received: by out.sender.test; Sat, 26 Sep 2026 10:00:00 +0000\r\n" +
			"From: a@sender.test\r\n\r\nbody\r\n")
	}

	assert.Equal(t, provenance.TrustTrusted, resolve("work", raw("dmarc=pass header.from=sender.test")).Trust)
	assert.Equal(t, provenance.TrustUnknown, resolve("work", raw("dmarc=fail header.from=sender.test")).Trust,
		"a rule's trusted outcome is gated")
	assert.Equal(t, provenance.TrustUnknown, resolve("other", raw("dmarc=pass header.from=sender.test")).Trust,
		"an unconfigured inbox is unknown")
}
