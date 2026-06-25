package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// bucketName is the bbolt bucket holding the hash-chained log.
var bucketName = []byte("audit")

// Record is the caller-supplied content of an audit entry.
type Record struct {
	Event     string `json:"event"`
	Agent     string `json:"agent"`
	MessageID string `json:"message_id"`
}

// Entry is a persisted, hash-chained audit log entry. Hash binds PrevHash and
// the entry payload, so any tampering or truncation breaks the chain (ADR 0011).
type Entry struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Record   Record    `json:"record"`
	PrevHash string    `json:"prev_hash"` // hex of the previous entry's hash ("" for the first)
	Hash     string    `json:"hash"`      // hex of this entry's hash
}

// EnsureBucket creates the audit bucket if it is missing. Call inside a
// writable transaction (e.g. from the store's open path).
func EnsureBucket(tx *bbolt.Tx) error {
	_, err := tx.CreateBucketIfNotExists(bucketName)
	return err
}

// Append writes a hash-chained entry within the given writable transaction, so
// it commits atomically with whatever the caller is doing in the same tx (the
// enqueue that triggered it). It reads the chain head, links to it, and stores
// the new entry.
func Append(tx *bbolt.Tx, rec Record) (Entry, error) {
	b := tx.Bucket(bucketName)
	if b == nil {
		return Entry{}, fmt.Errorf("audit: bucket %q missing", bucketName)
	}

	prevHash := ""
	if _, last := b.Cursor().Last(); last != nil {
		var prev Entry
		if err := json.Unmarshal(last, &prev); err != nil {
			return Entry{}, fmt.Errorf("audit: decode chain head: %w", err)
		}
		prevHash = prev.Hash
	}

	seq, err := b.NextSequence()
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Seq: seq, Time: time.Now().UTC(), Record: rec, PrevHash: prevHash}
	e.Hash = computeHash(prevHash, e)

	enc, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if err := b.Put(itob(seq), enc); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Verify walks the chain in order and returns an error at the first entry whose
// PrevHash link or own hash is inconsistent — evidence of tampering or
// truncation. An empty (or absent) log verifies clean.
func Verify(tx *bbolt.Tx) error {
	b := tx.Bucket(bucketName)
	if b == nil {
		return nil
	}
	prevHash := ""
	return b.ForEach(func(_, v []byte) error {
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		if e.PrevHash != prevHash {
			return fmt.Errorf("audit: chain broken at seq %d: prev_hash link mismatch", e.Seq)
		}
		if want := computeHash(prevHash, e); want != e.Hash {
			return fmt.Errorf("audit: chain broken at seq %d: hash mismatch", e.Seq)
		}
		prevHash = e.Hash
		return nil
	})
}

// computeHash is the deterministic chain hash: sha256(prevHash || payload),
// where payload is the entry without its own Hash field.
func computeHash(prevHash string, e Entry) string {
	payload := struct {
		Seq    uint64    `json:"seq"`
		Time   time.Time `json:"time"`
		Record Record    `json:"record"`
	}{e.Seq, e.Time, e.Record}
	pj, _ := json.Marshal(payload)

	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(pj)
	return hex.EncodeToString(h.Sum(nil))
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
