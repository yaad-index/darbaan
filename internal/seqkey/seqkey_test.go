package seqkey_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/seqkey"
)

func TestEncodeFixedWidthBigEndian(t *testing.T) {
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, seqkey.Encode(1))
	assert.Len(t, seqkey.Encode(0), 8)
}

func TestEncodeOrdersBySequence(t *testing.T) {
	// Lexicographic byte order must match numeric order, including across the
	// 8-bit boundary, so a bbolt cursor yields records in sequence order.
	for _, p := range [][2]uint64{{1, 2}, {255, 256}, {999, 1000}} {
		assert.Negative(t, bytes.Compare(seqkey.Encode(p[0]), seqkey.Encode(p[1])),
			"Encode(%d) should sort before Encode(%d)", p[0], p[1])
	}
}
