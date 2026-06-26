package inbound

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/blobstore"
	"github.com/yaad-index/darbaan/internal/seqkey"
)

var bucketInbound = []byte("inbound")

func init() {
	Register("bbolt", newBbolt)
}

// stored is the bbolt record: message metadata plus the tiering flag. The raw
// bytes live in a blob (Blobbed=true; Message.Raw is nil here), except for
// legacy records written before ADR 0018, which have Blobbed=false and the raw
// inline. Subject is already a stored field, so only the raw is reassembled.
//
// Unlike the sluice (whose List returns blob-free Meta), inbound's List returns
// full Messages and reassembles Raw from blobs — the IMAP face snapshots the raw
// at SELECT for FETCH/SEARCH. That eager read-time load is removed by the future
// lazy-inbound-sync work (ADR 0018 names it as future); this change is the
// storage tier only, keeping bbolt small regardless of mailbox size.
type stored struct {
	Message
	Blobbed bool `json:"blobbed,omitempty"`
}

// bboltStore is the bbolt-backed InboundStore. Metadata lives in its database;
// raw content lives in a per-store blob directory.
type bboltStore struct {
	db    *bbolt.DB
	blobs *blobstore.Store
}

func newBbolt(path string) (InboundStore, error) {
	if path == "" {
		return nil, fmt.Errorf("inbound: bbolt requires a database path (inbound-db)")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("inbound: open db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketInbound)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inbound: init bucket: %w", err)
	}
	// Per-store blob directory (<data>/blobs/inbound/), namespaced by the db name
	// so the sluice and inbound stores never collide on their per-store ids.
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	blobs, err := blobstore.New(filepath.Join(filepath.Dir(path), "blobs", base))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inbound: open blob store: %w", err)
	}
	store := &bboltStore{db: db, blobs: blobs}
	// Reclaim blobs orphaned by a crash between blob and metadata writes. Safe at
	// open: no concurrent writers yet (#83).
	if err := store.sweepOrphans(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inbound: sweep orphan blobs: %w", err)
	}
	return store, nil
}

// sweepOrphans deletes blobs with no referencing metadata record (#83). It is
// run at open, before serving.
func (s *bboltStore) sweepOrphans() error {
	live := map[string]bool{}
	if err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).ForEach(func(_, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			live[rec.ID] = true
			return nil
		})
	}); err != nil {
		return err
	}
	n, err := s.blobs.SweepOrphans(live)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("darbaan: inbound reclaimed %d orphan blob(s) at startup", n)
	}
	return nil
}

func (s *bboltStore) Close() error { return s.db.Close() }

func (s *bboltStore) Add(d Delivery) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbound)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		msg = Message{
			ID:         strconv.FormatUint(seq, 10),
			Owner:      d.Owner,
			From:       d.From,
			To:         d.To,
			Subject:    d.Subject,
			Raw:        d.Raw,
			Seen:       false,
			ReceivedAt: time.Now().UTC(),
		}
		// Content tier first: the durable blob is on disk before the referencing
		// metadata commits (ADR 0018), so a crash can only orphan a blob.
		if err := s.blobs.Put(msg.ID, d.Raw); err != nil {
			return fmt.Errorf("write content: %w", err)
		}
		return putStored(tx, seqkey.Encode(seq), storedFrom(msg))
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: add: %w", err)
	}
	return msg, nil
}

func (s *bboltStore) List(owner string) ([]Message, error) {
	var recs []stored
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).ForEach(func(_, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Owner == owner {
				recs = append(recs, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("inbound: list: %w", err)
	}
	// Reassemble each message's raw from its blob outside the txn, so file IO
	// never holds the read transaction.
	out := make([]Message, 0, len(recs))
	for _, rec := range recs {
		msg, err := s.withRaw(rec)
		if err != nil {
			return nil, fmt.Errorf("inbound: list: %w", err)
		}
		out = append(out, msg)
	}
	return out, nil
}

func (s *bboltStore) SetSeen(owner, id string, seen bool) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if rec.Owner != owner {
			return ErrNotFound // do not touch another owner's message
		}
		if rec.Seen == seen {
			return nil
		}
		rec.Seen = seen
		return putStored(tx, key, rec) // metadata only; the blob is untouched
	})
}

func (s *bboltStore) Get(owner, id string) (Message, error) {
	var rec stored
	err := s.db.View(func(tx *bbolt.Tx) error {
		r, _, e := loadStored(tx, id)
		if e != nil {
			return e
		}
		if r.Owner != owner {
			return ErrNotFound // do not leak another owner's message
		}
		rec = r
		return nil
	})
	if err != nil {
		return Message{}, err
	}
	return s.withRaw(rec)
}

// withRaw reassembles the full message: metadata plus the raw content from the
// blob (or, for a legacy record, the inline raw it already carries).
func (s *bboltStore) withRaw(rec stored) (Message, error) {
	msg := rec.Message
	if rec.Blobbed {
		raw, err := s.blobs.Get(msg.ID)
		if err != nil {
			return Message{}, fmt.Errorf("inbound: load content %s: %w", msg.ID, err)
		}
		msg.Raw = raw
	}
	return msg, nil
}

// storedFrom builds a blobbed metadata record from a full message: the raw bytes
// are dropped (they live in the blob).
func storedFrom(m Message) stored {
	m.Raw = nil
	return stored{Message: m, Blobbed: true}
}

func loadStored(tx *bbolt.Tx, id string) (stored, []byte, error) {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return stored{}, nil, fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	key := seqkey.Encode(seq)
	v := tx.Bucket(bucketInbound).Get(key)
	if v == nil {
		return stored{}, nil, ErrNotFound
	}
	var rec stored
	if err := json.Unmarshal(v, &rec); err != nil {
		return stored{}, nil, err
	}
	return rec, key, nil
}

func putStored(tx *bbolt.Tx, key []byte, rec stored) error {
	enc, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketInbound).Put(key, enc)
}
