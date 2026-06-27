package inbound

import (
	"encoding/binary"
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

var (
	bucketInbound = []byte("inbound")
	// bucketSynced indexes upstream-pulled messages by (owner, UIDVALIDITY, UID)
	// for idempotent re-sync (ADR 0019); value is the message's bucketInbound key.
	bucketSynced = []byte("synced")
)

func init() {
	Register("bbolt", newBbolt)
}

// stored is the bbolt record: message metadata plus the tiering flag. The raw
// bytes live in a blob (Blobbed=true; Message.Raw is nil here), except for legacy
// records written before ADR 0018 (Blobbed=false, raw inline) and pending records
// (Message.Pending=true, no content yet — ADR 0019). Subject is metadata.
//
// List returns metadata only (no blob reads): the IMAP read face snapshots
// metadata at SELECT and fetches a message's content per-FETCH via Get / the
// content fetcher (ADR 0019), so bbolt stays small and SELECT never reassembles
// the whole mailbox.
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
		if _, e := tx.CreateBucketIfNotExists(bucketInbound); e != nil {
			return e
		}
		_, e := tx.CreateBucketIfNotExists(bucketSynced)
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
		var e error
		msg, _, e = s.put(tx, d, false)
		return e
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: add: %w", err)
	}
	return msg, nil
}

// AddSynced stores an upstream-pulled message (with content) idempotently.
func (s *bboltStore) AddSynced(d Delivery) (bool, Message, error) {
	return s.addSynced(d, false)
}

// AddSyncedPending stores a headers-only (pending) record idempotently — no
// content blob; SetContent fills it later (lazy sync, ADR 0019).
func (s *bboltStore) AddSyncedPending(d Delivery) (bool, Message, error) {
	return s.addSynced(d, true)
}

// addSynced is the shared dedup path: if the upstream (owner, UIDValidity,
// UpstreamUID) is already indexed it's a no-op (added=false, returns the
// existing record), so a crash-mid-sync re-fetch never duplicates (#87);
// otherwise it stores the message (pending or present) and indexes it.
func (s *bboltStore) addSynced(d Delivery, pending bool) (bool, Message, error) {
	if d.UpstreamUID == 0 {
		return false, Message{}, fmt.Errorf("inbound: AddSynced requires a non-zero upstream UID")
	}
	idxKey := syncedKey(d.Owner, d.UIDValidity, d.UpstreamUID)
	var (
		added bool
		msg   Message
	)
	err := s.db.Update(func(tx *bbolt.Tx) error {
		idx := tx.Bucket(bucketSynced)
		if ref := idx.Get(idxKey); ref != nil {
			if v := tx.Bucket(bucketInbound).Get(ref); v != nil {
				var rec stored
				if err := json.Unmarshal(v, &rec); err != nil {
					return err
				}
				msg = rec.Message
			}
			return nil
		}
		m, key, err := s.put(tx, d, pending)
		if err != nil {
			return err
		}
		added, msg = true, m
		return idx.Put(idxKey, key)
	})
	if err != nil {
		return false, Message{}, fmt.Errorf("inbound: add synced: %w", err)
	}
	return added, msg, nil
}

// SetContent fills a pending message's body: write the content blob and mark the
// record present. Owner-scoped; returns the now-complete message.
func (s *bboltStore) SetContent(owner, id string, raw []byte) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if rec.Owner != owner {
			return ErrNotFound
		}
		// Content blob first, then the metadata flip (same ordering as Add).
		if err := s.blobs.Put(id, raw); err != nil {
			return fmt.Errorf("write content: %w", err)
		}
		rec.Pending = false
		rec.Blobbed = true
		msg = rec.Message
		msg.Raw = raw
		return putStored(tx, key, rec)
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: set content %s: %w", id, err)
	}
	return msg, nil
}

// put builds and persists a new message. For a present message it writes the
// content blob first (ADR 0018 ordering); a pending message has no blob yet.
// Returns the message and its bbolt key. The caller is inside a write txn.
func (s *bboltStore) put(tx *bbolt.Tx, d Delivery, pending bool) (Message, []byte, error) {
	b := tx.Bucket(bucketInbound)
	seq, err := b.NextSequence()
	if err != nil {
		return Message{}, nil, err
	}
	msg := Message{
		ID:          strconv.FormatUint(seq, 10),
		Owner:       d.Owner,
		From:        d.From,
		To:          d.To,
		Subject:     d.Subject,
		Seen:        false,
		ReceivedAt:  time.Now().UTC(),
		UpstreamUID: d.UpstreamUID,
		UIDValidity: d.UIDValidity,
		Pending:     pending,
	}
	key := seqkey.Encode(seq)
	blobbed := false
	if !pending {
		msg.Raw = d.Raw // present (return carries it; storedRec drops it for storage)
		if err := s.blobs.Put(msg.ID, d.Raw); err != nil {
			return Message{}, nil, fmt.Errorf("write content: %w", err)
		}
		blobbed = true
	}
	if err := putStored(tx, key, storedRec(msg, blobbed)); err != nil {
		return Message{}, nil, err
	}
	return msg, key, nil
}

// syncedKey is the dedup index key for an upstream message: owner + UIDVALIDITY
// + UID. UIDVALIDITY is included because UIDs are only unique within it.
func syncedKey(owner string, uidValidity, uid uint32) []byte {
	k := make([]byte, 0, len(owner)+1+8)
	k = append(k, owner...)
	k = append(k, 0) // separator (an owner name has no NUL)
	var n [8]byte
	binary.BigEndian.PutUint32(n[0:4], uidValidity)
	binary.BigEndian.PutUint32(n[4:8], uid)
	return append(k, n[:]...)
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
	// Metadata only: List never loads content (no blob reads, no eager mailbox
	// reassembly at SELECT). Callers fetch a message's body on demand via Get /
	// the content fetcher (ADR 0019).
	out := make([]Message, 0, len(recs))
	for _, rec := range recs {
		m := rec.Message
		m.Raw = nil
		out = append(out, m)
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
	switch {
	case msg.Pending:
		// Content not fetched yet — Raw stays nil; the caller fetches on demand.
	case rec.Blobbed:
		raw, err := s.blobs.Get(msg.ID)
		if err != nil {
			return Message{}, fmt.Errorf("inbound: load content %s: %w", msg.ID, err)
		}
		msg.Raw = raw
	default:
		// Legacy inline record — Raw is already inline on rec.Message.
	}
	return msg, nil
}

// storedRec builds the on-disk record from a message: the raw bytes are dropped
// (they live in a blob when blobbed; a pending record has none yet).
func storedRec(m Message, blobbed bool) stored {
	m.Raw = nil
	return stored{Message: m, Blobbed: blobbed}
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
