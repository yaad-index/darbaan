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

// adminAddrIsExposed warns only for a routable literal IP — not loopback, and not
// the unspecified address (0.0.0.0/::, the documented container pattern where the
// host narrows exposure). A hostname or unparseable addr never raises a false alarm.
func TestAdminAddrIsExposed(t *testing.T) {
	exposed := []string{"192.168.1.5:1144", "10.0.0.2:1144", "[2001:db8::1]:1144"}
	for _, a := range exposed {
		assert.Truef(t, adminAddrIsExposed(a), "%s is routable and should warn", a)
	}
	safe := []string{
		"127.0.0.1:1144",      // loopback v4
		"[::1]:1144",          // loopback v6
		"0.0.0.0:1144",        // unspecified — container pattern, host narrows exposure
		"[::]:1144",           // unspecified v6
		"localhost:1144",      // hostname, not a literal IP
		"admin.internal:1144", // hostname
		"garbage",             // no host:port
		"",
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
