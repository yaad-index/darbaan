package sluice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/blobstore"
	"github.com/yaad-index/darbaan/internal/seqkey"
)

// bucketMessages holds the held messages' metadata, keyed by big-endian sequence
// so a cursor iterates them in receive order. The raw content lives in the blob
// store, not here (ADR 0018).
var bucketMessages = []byte("messages")

func init() {
	Register("bbolt", newBbolt)
}

// stored is the bbolt record: message metadata plus the tiering fields. The raw
// bytes live in a blob (Blobbed=true; Message.Raw is nil here) — except for
// legacy records written before ADR 0018, which have Blobbed=false and the raw
// inline in Message.Raw. Subject and Size are persisted so List never reads a
// blob; legacy records lack them and derive from the inline raw instead.
type stored struct {
	Message
	Subject string `json:"subject,omitempty"`
	Size    int    `json:"size,omitempty"`
	Blobbed bool   `json:"blobbed,omitempty"`
}

// bboltStore is the bbolt-backed MessageStore. Metadata lives in its database;
// raw content lives in a per-store blob directory. It writes a best-effort audit
// entry to the (separate) audit log after each commit.
type bboltStore struct {
	db    *bbolt.DB
	blobs *blobstore.Store
	audit audit.AuditLog
}

func newBbolt(path string, al audit.AuditLog) (MessageStore, error) {
	if path == "" {
		return nil, fmt.Errorf("sluice: bbolt requires a database path (sluice-db)")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("sluice: open db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketMessages)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sluice: init bucket: %w", err)
	}
	// Per-store blob directory (e.g. <data>/blobs/sluice/), namespaced by the db
	// name so stores never collide on a shared id space.
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	blobs, err := blobstore.New(filepath.Join(filepath.Dir(path), "blobs", base))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sluice: open blob store: %w", err)
	}
	store := &bboltStore{db: db, blobs: blobs, audit: al}
	// Reclaim blobs orphaned by a crash between blob and metadata writes. Safe at
	// open: no concurrent writers yet (#83).
	if err := store.sweepOrphans(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sluice: sweep orphan blobs: %w", err)
	}
	return store, nil
}

// sweepOrphans deletes blobs with no referencing metadata record (#83). It is
// run at open, before serving.
func (s *bboltStore) sweepOrphans() error {
	live := map[string]bool{}
	if err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketMessages).ForEach(func(_, v []byte) error {
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
		slog.Info("sluice reclaimed orphan blobs at startup", "count", n)
	}
	return nil
}

func (s *bboltStore) Close() error { return s.db.Close() }

// writeAudit records an entry after the message-store commit. It is best-effort:
// the message is already durably committed (the source of truth), so a failed
// audit append is logged, not returned — it must not fail the operation or
// (for Enqueue) cause an SMTP-level retry of an already-trapped message
// (ADR 0011, #17 trade-off).
func (s *bboltStore) writeAudit(rec audit.Record) {
	if err := s.audit.Append(rec); err != nil {
		slog.Warn("best-effort audit append failed", "message_id", rec.MessageID, "event", rec.Event, "err", err)
	}
}

func (s *bboltStore) Enqueue(sub Submission) (Message, error) {
	var msg Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMessages)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		msg = Message{
			ID:         strconv.FormatUint(seq, 10),
			Agent:      sub.Agent,
			Inbox:      sub.Inbox,
			From:       sub.From,
			Rcpt:       append([]string(nil), sub.Rcpt...),
			Raw:        sub.Raw,
			ReceivedAt: time.Now().UTC(),
			Status:     StatusPending,
		}
		// Content tier first: the blob is durable before the referencing metadata
		// commits (ADR 0018), so a crash can only orphan a blob, never dangle a
		// metadata pointer.
		if err := s.blobs.Put(msg.ID, sub.Raw); err != nil {
			return fmt.Errorf("write content: %w", err)
		}
		return putStored(tx, seqkey.Encode(seq), storedFrom(msg))
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: enqueue: %w", err)
	}
	s.writeAudit(audit.Record{Event: "enqueue", Agent: msg.Agent, Inbox: msg.Inbox, MessageID: msg.ID})
	return msg, nil
}

func (s *bboltStore) List() ([]Meta, error) {
	var metas []Meta
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketMessages).ForEach(func(_, v []byte) error {
			var rec stored
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			subject, size := rec.Subject, rec.Size
			if !rec.Blobbed { // legacy inline record: derive (no persisted subject/size)
				subject = subjectFromRaw(rec.Raw)
				size = len(rec.Raw)
			}
			metas = append(metas, Meta{
				ID:         rec.ID,
				Agent:      rec.Agent,
				Inbox:      rec.Inbox,
				From:       rec.From,
				Rcpt:       rec.Rcpt,
				Subject:    subject,
				Size:       size,
				ReceivedAt: rec.ReceivedAt,
				Status:     rec.Status,
				SendErr:    rec.SendErr,
			})
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("sluice: list: %w", err)
	}
	return metas, nil
}

func (s *bboltStore) Get(id string) (Message, error) {
	var rec stored
	err := s.db.View(func(tx *bbolt.Tx) error {
		var e error
		rec, _, e = loadStored(tx, id)
		return e
	})
	if err != nil {
		return Message{}, err
	}
	return s.withRaw(rec)
}

func (s *bboltStore) Approve(id, decidedBy string, released []byte, asInbox, actor string) (Message, error) {
	return s.transitionFromPending(id, "approve", decidedBy, actor, nil, func(m *Message) {
		m.Status = StatusApproved
		m.DecidedBy = decidedBy
		// An amended body (ADR 0004) is recorded inline; it is nil in v1 (no
		// amendment flow) — tiering Released pairs with that feature (follow-up).
		if len(released) > 0 {
			m.Released = released
		}
		// Record the ApproveAs identity choice as decision metadata (ADR 0023 slice
		// 5): the stored body is unchanged, but a re-send recomputes the From
		// rewrite from this inbox instead of silently reverting to the original.
		m.AsInbox = asInbox
	})
}

func (s *bboltStore) Reject(id, decidedBy, reason string, retryable bool, actor string) (Message, error) {
	out, err := s.transitionFromPending(id, "reject", reason, actor, &retryable, func(m *Message) {
		m.Status = StatusRejected
		m.DecidedBy = decidedBy
		m.Reason = reason
		m.Retryable = retryable
	})
	if err == nil && !retryable {
		// A permanent (5xx) reject is an operator security signal (ADR 0006, C28):
		// surface it loudly, distinct from the routine transient reject.
		slog.Warn("outbound message permanently rejected", "message_id", id, "agent", out.Agent, "inbox", out.Inbox, "actor", actor)
	}
	return out, err
}

func (s *bboltStore) RecordSendAttempt(id string, sendErr error, resend bool, actor, asIdentity string) (Message, error) {
	detail := "sent"
	if asIdentity != "" {
		detail = "sent as " + asIdentity // ApproveAs identity, audited (C16)
	}
	var out Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		rec, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		// A send is only ever recorded against an approved message. An already-sent
		// message admits only an idempotent SUCCESS re-record — never a failure
		// stamp, so a losing concurrent second attempt can't turn a delivered
		// message into sent-with-error (C26 + review). Pending/rejected are refused.
		switch {
		case rec.Status == StatusApproved:
		case rec.Status == StatusSent && sendErr == nil:
		default:
			return fmt.Errorf("%w: message %s is %s", ErrNotApproved, id, rec.Status)
		}
		if sendErr != nil {
			rec.SendErr = sendErr.Error() // stays approved for a manual re-send
		} else {
			rec.Status = StatusSent // delivered upstream
			rec.SendErr = ""
		}
		// The caller uses only the updated status; the raw body is not
		// reassembled here, so a send never re-reads a (possibly large) blob.
		out = rec.Message
		return putStored(tx, key, rec)
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: record send attempt: %w", err)
	}
	if sendErr != nil {
		detail = sendErr.Error()
		if asIdentity != "" {
			detail += " (as " + asIdentity + ")"
		}
	}
	// A re-send is a distinct, operator-triggered delivery — audit it under its own
	// event so it is not indistinguishable from the first send in the durable log.
	event := "send_attempt"
	if resend {
		event = "resend_attempt"
	}
	s.writeAudit(audit.Record{Event: event, Agent: out.Agent, Inbox: out.Inbox, Actor: actor, MessageID: id, Detail: detail})
	return out, nil
}

// transitionFromPending commits a status change to a pending message, then
// writes a best-effort audit entry. It errors if the message is not pending, so
// a verdict can never be applied twice. The returned message includes the raw
// body (the approve/reject callers send it / attach it to a bounce).
func (s *bboltStore) transitionFromPending(id, event, detail, actor string, retryable *bool, mutate func(*Message)) (Message, error) {
	var rec stored
	err := s.db.Update(func(tx *bbolt.Tx) error {
		r, key, err := loadStored(tx, id)
		if err != nil {
			return err
		}
		if r.Status != StatusPending {
			return fmt.Errorf("%w: %s is %s", ErrNotPending, id, r.Status)
		}
		mutate(&r.Message)
		rec = r
		return putStored(tx, key, r)
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: %s: %w", event, err)
	}
	out, err := s.withRaw(rec)
	if err != nil {
		return Message{}, err
	}
	s.writeAudit(audit.Record{Event: event, Agent: out.Agent, Inbox: out.Inbox, Actor: actor, MessageID: id, Detail: detail, Retryable: retryable})
	return out, nil
}

// withRaw reassembles the full message: metadata from the record plus the raw
// content from the blob (or, for a legacy record, the inline raw it already
// carries).
func (s *bboltStore) withRaw(rec stored) (Message, error) {
	msg := rec.Message
	if rec.Blobbed {
		raw, err := s.blobs.Get(msg.ID)
		if err != nil {
			return Message{}, fmt.Errorf("sluice: load content %s: %w", msg.ID, err)
		}
		msg.Raw = raw
	}
	return msg, nil
}

// storedFrom builds a blobbed metadata record from a full message: the raw bytes
// are dropped (they live in the blob) and subject/size are persisted so List
// never needs the blob.
func storedFrom(m Message) stored {
	subject := subjectFromRaw(m.Raw)
	size := len(m.Raw)
	m.Raw = nil
	return stored{Message: m, Subject: subject, Size: size, Blobbed: true}
}

func loadStored(tx *bbolt.Tx, id string) (stored, []byte, error) {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return stored{}, nil, fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	key := seqkey.Encode(seq)
	v := tx.Bucket(bucketMessages).Get(key)
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
	return tx.Bucket(bucketMessages).Put(key, enc)
}
