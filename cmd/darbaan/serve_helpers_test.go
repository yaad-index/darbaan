package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// A non-positive poll interval is clamped to the default so time.NewTicker — which
// panics on a duration <= 0 — cannot crash serve; a positive one passes through,
// and ok reports whether a clamp was applied. The resolved value is always positive.
func TestResolvePollInterval(t *testing.T) {
	cases := []struct {
		in     time.Duration
		want   time.Duration
		wantOK bool
	}{
		{0, defaultInboundPollInterval, false},
		{-5 * time.Second, defaultInboundPollInterval, false},
		{-1 * time.Nanosecond, defaultInboundPollInterval, false},
		{30 * time.Second, 30 * time.Second, true},
		{defaultInboundPollInterval, defaultInboundPollInterval, true},
		{1 * time.Nanosecond, 1 * time.Nanosecond, true},
	}
	for _, c := range cases {
		got, ok := resolvePollInterval(c.in)
		assert.Equalf(t, c.want, got, "interval for %v", c.in)
		assert.Equalf(t, c.wantOK, ok, "ok for %v", c.in)
		assert.Truef(t, got > 0, "resolved interval must be positive (time.NewTicker) for %v", c.in)
	}
}

// adminAddrIsExposed warns on any literal IP that is not loopback — routable, the
// every-interface binds (unspecified 0.0.0.0/:: and the empty host of a bare
// ":port"), and a zone-carrying literal (link-local OR global). A literal loopback
// IP (incl. zoned and 4-in-6 forms), a hostname (not resolved here), and a
// malformed/unparseable addr stay silent. Routable examples use documentation ranges
// (RFC 5737 / 3849), not real infrastructure addresses.
func TestAdminAddrIsExposed(t *testing.T) {
	exposed := []string{
		"192.0.2.10:1144",         // TEST-NET-1 routable v4
		"198.51.100.5:1144",       // TEST-NET-2 routable v4
		"[2001:db8::1]:1144",      // documentation range v6
		"0.0.0.0:1144",            // unspecified v4 — every interface
		"[::]:1144",               // unspecified v6 — every interface
		":1144",                   // bare port, empty host — every interface
		"[fe80::1%eth0]:1144",     // zoned link-local literal — binds an interface
		"[2001:db8::1%eth0]:1144", // zoned GLOBAL literal — reachable, still a literal bind
	}
	for _, a := range exposed {
		assert.Truef(t, adminAddrIsExposed(a), "%q binds beyond loopback and should warn", a)
	}
	safe := []string{
		"127.0.0.1:1144",          // loopback v4
		"127.0.0.5:1144",          // 127.0.0.0/8 is all loopback, not just .1
		"[::1]:1144",              // loopback v6
		"[::1%lo0]:1144",          // zoned loopback — the zone is stripped/parsed, loopback preserved
		"[::ffff:127.0.0.1]:1144", // 4-in-6 loopback — IsLoopback handles it with no Unmap
		"localhost:1144",          // hostname, not a literal IP — most common safe config
		"admin.internal:1144",     // hostname
		"[%eth0]:1144",            // malformed zone (no address) — unparseable, must NOT read as every-interface
		"garbage",                 // no host:port
		"",                        // unparseable
	}
	for _, a := range safe {
		assert.Falsef(t, adminAddrIsExposed(a), "%q must not warn", a)
	}
}

// The clamp fallback must equal the flag's own default, or a mis-set interval would
// fall back to a value the operator never documented. The flag tag is a string
// literal that cannot reference the const, so this guards the two against drifting.
func TestDefaultInboundPollIntervalMatchesFlag(t *testing.T) {
	cli := parseCLI(t, []string{"version"})
	assert.Equal(t, defaultInboundPollInterval, cli.InboundIMAPPollInterval,
		"defaultInboundPollInterval must match the inbound-imap-poll-interval flag default")
}
