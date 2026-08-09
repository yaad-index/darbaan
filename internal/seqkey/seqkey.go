// Package seqkey encodes uint64 sequence numbers as fixed-width, big-endian
// keys, so a bbolt cursor iterates records in sequence (i.e. receive) order.
// Shared by the audit log and the sluice, which both key buckets by sequence.
package seqkey

import "encoding/binary"

// Encode returns the 8-byte big-endian encoding of seq, suitable as an ordered
// bbolt key.
func Encode(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

// Decode reads back a key written by Encode. A key that is not exactly 8 bytes
// decodes to 0, which callers that pair keys with a stored sequence treat as a
// mismatch (the audit Verify uses it to assert key↔Seq agreement).
func Decode(key []byte) uint64 {
	if len(key) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(key)
}
