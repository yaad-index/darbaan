package inbound

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
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
	// KeywordsDirty marks a record whose local keyword set has not yet been
	// confirmed replicated to the upstream backend (ADR 0020 write-through). The
	// local store is canonical; the sync reconciles dirty records best-effort.
	KeywordsDirty bool `json:"keywords_dirty,omitempty"`
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
		slog.Info("inbound reclaimed orphan blobs at startup", "count", n)
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
	idxKey := syncedKey(d.Owner, d.Inbox, d.UIDValidity, d.UpstreamUID)
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
func (s *bboltStore) SetContent(owner, inbox, id string, raw []byte) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
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
		Inbox:       NormInbox(d.Inbox),
		From:        d.From,
		To:          d.To,
		Subject:     d.Subject,
		Seen:        false,
		ReceivedAt:  time.Now().UTC(),
		UpstreamUID: d.UpstreamUID,
		UIDValidity: d.UIDValidity,
		Pending:     pending,
		Envelope:    d.Envelope,
		Size:        d.Size,
		Keywords:    d.Keywords,
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

// syncedKey is the dedup index key for an upstream message: owner + inbox +
// UIDVALIDITY + UID. The inbox is included because each inbox is an independent
// upstream UID space (ADR 0023) — two inboxes (esp. on different accounts) can
// carry the same (UIDVALIDITY, UID), and must not collide in the dedup index.
// UIDVALIDITY is included because UIDs are only unique within it.
func syncedKey(owner, inbox string, uidValidity, uid uint32) []byte {
	inbox = NormInbox(inbox)
	k := make([]byte, 0, len(owner)+1+len(inbox)+1+8)
	k = append(k, owner...)
	k = append(k, 0) // separator (an owner name has no NUL)
	k = append(k, inbox...)
	k = append(k, 0)
	var n [8]byte
	binary.BigEndian.PutUint32(n[0:4], uidValidity)
	binary.BigEndian.PutUint32(n[4:8], uid)
	return append(k, n[:]...)
}

// recScoped reports whether a stored record belongs to (owner, inbox), treating a
// record with no Inbox (written before multi-inbox) as DefaultInbox.
func recScoped(rec stored, owner, inbox string) bool {
	return rec.Owner == owner && NormInbox(rec.Inbox) == NormInbox(inbox)
}

func (s *bboltStore) List(owner, inbox string) ([]Message, error) {
	var recs []stored
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).ForEach(func(_, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if recScoped(rec, owner, inbox) {
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

func (s *bboltStore) SetSeen(owner, inbox, id string, seen bool) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
			return ErrNotFound // do not touch another owner's/inbox's message
		}
		if rec.Seen == seen {
			return nil
		}
		rec.Seen = seen
		return putStored(tx, key, rec) // metadata only; the blob is untouched
	})
}

// RemoveSynced hard-removes an upstream-synced message (ADR 0026 reconciliation):
// its metadata record, its dedup-index entry, and its content blob. It refuses a
// locally-generated record (UpstreamUID == 0, e.g. a signed bounce) — those have
// no upstream and are never reconciled — and is (owner, inbox)-scoped.
//
// The metadata record and the dedup-index entry are removed in one txn; the blob
// is deleted AFTER the commit. The ordering mirrors the blob-first WRITE path
// (put/SetContent, ADR 0018) inverted: removing metadata first means a crash
// before the blob delete only ORPHANS the blob (no record references it), which
// the startup sweep reclaims — it can never leave a metadata pointer to a missing
// blob.
func (s *bboltStore) RemoveSynced(owner, inbox, id string) error {
	var blobbed bool
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
			return ErrNotFound // do not retract another owner's/inbox's message
		}
		if rec.UpstreamUID == 0 {
			return fmt.Errorf("refusing to retract locally-generated message %s (no upstream UID)", id)
		}
		if err := tx.Bucket(bucketInbound).Delete(key); err != nil {
			return err
		}
		// Clear the dedup index so the message re-syncs cleanly if it returns to the
		// source later (ADR 0026 re-appearance): a stale index entry would suppress
		// the re-add as a false duplicate.
		idxKey := syncedKey(rec.Owner, rec.Inbox, rec.UIDValidity, rec.UpstreamUID)
		if err := tx.Bucket(bucketSynced).Delete(idxKey); err != nil {
			return err
		}
		blobbed = rec.Blobbed
		return nil
	})
	if err != nil {
		return fmt.Errorf("inbound: remove synced %s: %w", id, err)
	}
	if blobbed {
		// Best-effort: a present record's blob. Delete is idempotent (a missing blob
		// is not an error); a real failure only orphans it for the next sweep.
		if err := s.blobs.Delete(id); err != nil {
			slog.Warn("inbound retract: blob delete failed (orphan, will be swept)", "id", id, "err", err)
		}
	}
	return nil
}

// RekeyOwnersToInbox rewrites every synced record's owner key to its inbox name
// (ADR 0027). Bounces and other locally-generated records (UpstreamUID == 0) are
// left keyed to their originating agent — private to it. The synced dedup index
// moves with each record so a later re-sync still dedups. Idempotent: a record
// already inbox-owned is skipped.
func (s *bboltStore) RekeyOwnersToInbox() (int, error) {
	type item struct {
		key []byte
		rec stored
	}
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		inb := tx.Bucket(bucketInbound)
		idx := tx.Bucket(bucketSynced)
		// Collect first (copying keys); mutating a bucket during its own ForEach is
		// unsafe.
		var work []item
		if err := inb.ForEach(func(k, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.UpstreamUID == 0 {
				return nil // locally-generated (e.g. bounce): keep the originating owner
			}
			if rec.Owner == NormInbox(rec.Inbox) {
				return nil // already inbox-owned
			}
			kc := make([]byte, len(k))
			copy(kc, k)
			work = append(work, item{key: kc, rec: rec})
			return nil
		}); err != nil {
			return err
		}
		for _, w := range work {
			want := NormInbox(w.rec.Inbox)
			oldIdx := syncedKey(w.rec.Owner, w.rec.Inbox, w.rec.UIDValidity, w.rec.UpstreamUID)
			newIdx := syncedKey(want, w.rec.Inbox, w.rec.UIDValidity, w.rec.UpstreamUID)
			if err := idx.Delete(oldIdx); err != nil {
				return err
			}
			if err := idx.Put(newIdx, w.key); err != nil {
				return err
			}
			w.rec.Owner = want
			if err := putStored(tx, w.key, w.rec); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("inbound: rekey owners: %w", err)
	}
	return n, nil
}

// SetKeywords replaces the owner's message's keyword set (ADR 0020) and marks it
// dirty for upstream reconcile. The local store is canonical; the returned
// message carries the new keywords (without content). Metadata-only write.
func (s *bboltStore) SetKeywords(owner, inbox, id string, keywords []string) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
			return ErrNotFound
		}
		rec.Keywords = keywords
		// Only mark dirty when there is an upstream to replicate to. A
		// locally-generated record (no UpstreamUID, e.g. a bounce) has no backend
		// label to sync, so it must never enter reconcile (which would log on every
		// poll). Its keywords are local-only and already "replicated".
		rec.KeywordsDirty = rec.UpstreamUID != 0
		msg = rec.Message
		return putStored(tx, key, rec)
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: set keywords %s: %w", id, err)
	}
	return msg, nil
}

// ClearKeywordsDirty clears the dirty flag after a successful upstream replicate.
func (s *bboltStore) ClearKeywordsDirty(owner, inbox, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
			return ErrNotFound
		}
		if !rec.KeywordsDirty {
			return nil
		}
		rec.KeywordsDirty = false
		return putStored(tx, key, rec)
	})
}

// SetHoldDecision persists the human's hold-for-human decision (ADR 0021) on the
// owner's message (metadata only; the blob is untouched) and returns it.
func (s *bboltStore) SetHoldDecision(owner, inbox, id, decision string) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if !recScoped(rec, owner, inbox) {
			return ErrNotFound
		}
		rec.HoldDecision = decision
		msg = rec.Message
		return putStored(tx, key, rec)
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: set hold decision %s: %w", id, err)
	}
	return msg, nil
}

// DirtyKeywords returns the owner's messages whose keywords await upstream
// replication (metadata only), for the sync to reconcile.
func (s *bboltStore) DirtyKeywords(owner, inbox string) ([]Message, error) {
	var out []Message
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).ForEach(func(_, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.KeywordsDirty && recScoped(rec, owner, inbox) {
				out = append(out, rec.Message)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("inbound: dirty keywords: %w", err)
	}
	return out, nil
}

func (s *bboltStore) Get(owner, inbox, id string) (Message, error) {
	var rec stored
	err := s.db.View(func(tx *bbolt.Tx) error {
		r, _, e := loadStored(tx, id)
		if e != nil {
			return e
		}
		if !recScoped(r, owner, inbox) {
			return ErrNotFound // do not leak another owner's/inbox's message
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
