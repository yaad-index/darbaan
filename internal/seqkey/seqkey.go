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
