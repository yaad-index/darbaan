package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMaxAge(t *testing.T) {
	ok := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{" 1y ", 365 * 24 * time.Hour}, // trimmed
		{"1y", 365 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"12h", 12 * time.Hour},
		{"90m", 90 * time.Minute},
	}
	for _, c := range ok {
		got, err := parseMaxAge(c.in)
		require.NoError(t, err, c.in)
		assert.Equal(t, c.want, got, c.in)
	}

	// Negatives must be rejected on BOTH parse paths. "-1y"/"-2d" exercise the d/w/y
	// suffix path; "-24h"/"-1h30m"/"-30m"/"-500ms" exercise the time.ParseDuration
	// path, which accepts negative durations without error — the gap a single
	// post-parse sign gate closes (a negative cutoff selects "newer than the future").
	for _, bad := range []string{"abc", "1x", "yy", "-1y", "-2d", "-24h", "-1h30m", "-30m", "-500ms"} {
		_, err := parseMaxAge(bad)
		assert.Error(t, err, bad)
	}
}
