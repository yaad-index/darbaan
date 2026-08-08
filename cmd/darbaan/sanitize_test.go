package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// C22: sanitizeField must neutralize every control / bidi / zero-width rune an
// attacker can smuggle through a MIME encoded-word From/Subject, so the operator's
// terminal shows only inert text on the decision surface. The invisible runes are
// written as \u escapes so no hidden byte lives in this source.
func TestSanitizeFieldStripsTerminalControlRunes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"CRLF", "spoofed\r\nInjected: header"},
		{"ESC-CSI", "clear\x1b[2Jscreen"},
		{"NUL+BEL+DEL", "a\x00b\x07c\x7f"},
		{"C1-control", "a\x85b"},
		{"bidi-override-RLO", "user\u202egnp.exe"},
		{"bidi-isolate", "a\u2066b\u2069c"},
		{"zero-width", "acme\u200bcorp\u200d.example"},
		{"BOM", "\ufeffheader"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeField(tc.in)
			for _, r := range got {
				assert.Falsef(t, isDangerousRune(r), "rune %U survived sanitization in %q", r, got)
			}
		})
	}
}

// Ordinary text (including non-ASCII letters and legitimate spaces) passes through
// unchanged - sanitization must not mangle real subjects/senders.
func TestSanitizeFieldPreservesOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"Alice <alice@example.com>",
		"Re: quarterly report \U00002014cafe resume",
		"invoice \U000053d1\U00007968",
		"emoji ok \U0001f381",
	} {
		assert.Equal(t, s, sanitizeField(s))
	}
	// A control rune is replaced with U+FFFD exactly where it stood.
	assert.Equal(t, "a\ufffdb", sanitizeField("a\nb"))
	assert.NotContains(t, sanitizeField("x\ry"), "\r")
}

// isDangerousRune mirrors the classes sanitizeField neutralizes, for the
// post-condition assertion above.
func isDangerousRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x200e || r == 0x200f,
		r >= 0x202a && r <= 0x202e,
		r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff:
		return true
	}
	return false
}
