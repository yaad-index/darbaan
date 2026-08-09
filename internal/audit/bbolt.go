package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/seqkey"
)

var bucketName = []byte("audit")

func init() {
	Register("bbolt", newBbolt)
}

// bboltLog is the hash-chained, tamper-evident audit log, in its OWN bbolt
// database — separate from the message store (the audit separation in #17), so
// entries are appended here after the message-store commit completes.
type bboltLog struct{ db *bbolt.DB }

func newBbolt(path string) (AuditLog, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: bbolt requires a database path (audit-db)")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("audit: open db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketName)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: init bucket: %w", err)
	}
	return &bboltLog{db: db}, nil
}

// Append links a new entry into the hash chain in its own transaction.
func (l *bboltLog) Append(rec Record) error {
	return l.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)

		prevHash := ""
		if _, last := b.Cursor().Last(); last != nil {
			var prev Entry
			if err := json.Unmarshal(last, &prev); err != nil {
				return fmt.Errorf("audit: decode chain head: %w", err)
			}
			prevHash = prev.Hash
		}

		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		e := Entry{
			Seq:      seq,
			Time:     time.Now().UTC().Format(time.RFC3339Nano),
			Record:   rec,
			PrevHash: prevHash,
		}
		e.Hash = computeHash(prevHash, e)

		enc, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put(seqkey.Encode(seq), enc)
	})
}

// Verify walks the chain and reports the first integrity violation: a key that
// disagrees with its entry's Seq, a gap in the Seq run, a broken prev_hash link,
// or a hash mismatch — then confirms the tail is whole. It proves integrity, not
// cross-store completeness (see the AuditLog.Verify godoc).
func (l *bboltLog) Verify() error {
	return l.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		prevHash := ""
		var wantSeq uint64 = 1 // NextSequence issues 1 for the first entry
		var lastSeq uint64
		if err := b.ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			// The key IS the entry's Seq (seqkey-encoded): a record moved to a
			// different slot, or a Seq edited to fake continuity, disagrees here.
			if keySeq := seqkey.Decode(k); keySeq != e.Seq {
				return fmt.Errorf("audit: chain broken at key %d: entry seq is %d", keySeq, e.Seq)
			}
			// Seq must be a gap-free run from 1. A deleted interior entry, or a
			// truncate-then-append (which resumes at the higher, delete-proof
			// counter value), breaks the run — the check that makes truncation
			// evident rather than silently re-chained (ADR 0011).
			if e.Seq != wantSeq {
				return fmt.Errorf("audit: chain broken at seq %d: expected %d (gap or truncation)", e.Seq, wantSeq)
			}
			if e.PrevHash != prevHash {
				return fmt.Errorf("audit: chain broken at seq %d: prev_hash link mismatch", e.Seq)
			}
			if want := computeHash(prevHash, e); want != e.Hash {
				return fmt.Errorf("audit: chain broken at seq %d: hash mismatch", e.Seq)
			}
			prevHash = e.Hash
			lastSeq = e.Seq
			wantSeq++
			return nil
		}); err != nil {
			return err
		}
		// The bucket's sequence counter is monotonic and survives deletes, so the
		// last surviving entry's Seq must equal it. A truncated tail (delete the
		// last N with no re-append) leaves the counter ahead of the head — the
		// check that makes plain tail deletion evident, not just interior edits.
		// Completeness across the message store stays out of scope (a never-written
		// entry never advanced this counter); see the AuditLog.Verify godoc.
		if seq := b.Sequence(); seq != lastSeq {
			return fmt.Errorf("audit: tail truncated: last entry seq %d but %d were issued", lastSeq, seq)
		}
		return nil
	})
}

func (l *bboltLog) Close() error { return l.db.Close() }

// OpenReadOnly opens an existing bbolt audit log read-only for offline integrity
// verification (the `darbaan audit verify` command). It never writes and takes
// bbolt's shared lock, so it cannot run while a serve process holds the exclusive
// write lock — stop serve first, or it fails fast on the lock timeout. A missing
// bucket / empty database verifies clean.
func OpenReadOnly(path string) (AuditLog, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: bbolt requires a database path (audit-db)")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("audit: open db read-only: %w", err)
	}
	return &bboltLog{db: db}, nil
}

// computeHash is the deterministic chain hash: sha256(prevHash || payload),
// where payload is the entry without its own Hash field.
func computeHash(prevHash string, e Entry) string {
	payload := struct {
		Seq    uint64 `json:"seq"`
		Time   string `json:"time"`
		Record Record `json:"record"`
	}{e.Seq, e.Time, e.Record}
	pj, err := json.Marshal(payload)
	if err != nil {
		// payload is a fixed struct of marshalable types, so this cannot fail in
		// practice. But a security hash must never silently hash an empty payload
		// into a wrong-but-internally-consistent chain that still passes Verify.
		panic(fmt.Sprintf("audit: marshal hash payload: %v", err))
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(pj)
	return hex.EncodeToString(h.Sum(nil))
}
