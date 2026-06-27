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

	for _, bad := range []string{"abc", "1x", "yy", "-1y"} {
		_, err := parseMaxAge(bad)
		assert.Error(t, err, bad)
	}
}
