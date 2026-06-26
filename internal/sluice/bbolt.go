package sluice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/seqkey"
)

// bucketMessages holds the held messages, keyed by big-endian sequence so a
// cursor iterates them in receive order.
var bucketMessages = []byte("messages")

func init() {
	Register("bbolt", newBbolt)
}

// bboltStore is the bbolt-backed MessageStore. It commits messages to its own
// database, then writes a best-effort audit entry to the (separate) audit log.
type bboltStore struct {
	db    *bbolt.DB
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
	return &bboltStore{db: db, audit: al}, nil
}

func (s *bboltStore) Close() error { return s.db.Close() }

// writeAudit records an entry after the message-store commit. It is best-effort:
// the message is already durably committed (the source of truth), so a failed
// audit append is logged, not returned — it must not fail the operation or
// (for Enqueue) cause an SMTP-level retry of an already-trapped message
// (ADR 0011, #17 trade-off).
func (s *bboltStore) writeAudit(rec audit.Record) {
	if err := s.audit.Append(rec); err != nil {
		log.Printf("darbaan: best-effort audit append failed for message %s (%s): %v", rec.MessageID, rec.Event, err)
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
			From:       sub.From,
			Rcpt:       append([]string(nil), sub.Rcpt...),
			Raw:        sub.Raw,
			ReceivedAt: time.Now().UTC(),
			Status:     StatusPending,
		}
		enc, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return b.Put(seqkey.Encode(seq), enc)
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: enqueue: %w", err)
	}
	s.writeAudit(audit.Record{Event: "enqueue", Agent: msg.Agent, MessageID: msg.ID})
	return msg, nil
}

func (s *bboltStore) List() ([]Meta, error) {
	var metas []Meta
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketMessages).ForEach(func(_, v []byte) error {
			var m Message
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			metas = append(metas, Meta{
				ID:         m.ID,
				Agent:      m.Agent,
				From:       m.From,
				Rcpt:       m.Rcpt,
				Subject:    subjectFromRaw(m.Raw),
				Size:       len(m.Raw),
				ReceivedAt: m.ReceivedAt,
				Status:     m.Status,
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
	var msg Message
	err := s.db.View(func(tx *bbolt.Tx) error {
		var e error
		msg, _, e = loadMessage(tx, id)
		return e
	})
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

func (s *bboltStore) Approve(id, decidedBy string, released []byte) (Message, error) {
	return s.transitionFromPending(id, "approve", decidedBy, func(m *Message) {
		m.Status = StatusApproved
		m.DecidedBy = decidedBy
		if released != nil && !bytes.Equal(released, m.Raw) {
			m.Released = released
		}
	})
}

func (s *bboltStore) Reject(id, decidedBy, reason string, retryable bool) (Message, error) {
	return s.transitionFromPending(id, "reject", reason, func(m *Message) {
		m.Status = StatusRejected
		m.DecidedBy = decidedBy
		m.Reason = reason
		m.Retryable = retryable
	})
}

func (s *bboltStore) RecordSendAttempt(id string, sendErr error) (Message, error) {
	detail := "sent"
	var out Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		m, key, err := loadMessage(tx, id)
		if err != nil {
			return err
		}
		if sendErr != nil {
			m.SendErr = sendErr.Error() // stays approved for a manual re-send
		} else {
			m.Status = StatusSent // delivered upstream
			m.SendErr = ""
		}
		out = m
		return putMessage(tx, key, m)
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: record send attempt: %w", err)
	}
	if sendErr != nil {
		detail = sendErr.Error()
	}
	s.writeAudit(audit.Record{Event: "send_attempt", Agent: out.Agent, MessageID: id, Detail: detail})
	return out, nil
}

// transitionFromPending commits a status change to a pending message, then
// writes a best-effort audit entry. It errors if the message is not pending, so
// a verdict can never be applied twice.
func (s *bboltStore) transitionFromPending(id, event, detail string, mutate func(*Message)) (Message, error) {
	var out Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		m, key, err := loadMessage(tx, id)
		if err != nil {
			return err
		}
		if m.Status != StatusPending {
			return fmt.Errorf("%w: %s is %s", ErrNotPending, id, m.Status)
		}
		mutate(&m)
		out = m
		return putMessage(tx, key, m)
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: %s: %w", event, err)
	}
	s.writeAudit(audit.Record{Event: event, Agent: out.Agent, MessageID: id, Detail: detail})
	return out, nil
}

func loadMessage(tx *bbolt.Tx, id string) (Message, []byte, error) {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Message{}, nil, fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	key := seqkey.Encode(seq)
	v := tx.Bucket(bucketMessages).Get(key)
	if v == nil {
		return Message{}, nil, ErrNotFound
	}
	var m Message
	if err := json.Unmarshal(v, &m); err != nil {
		return Message{}, nil, err
	}
	return m, key, nil
}

func putMessage(tx *bbolt.Tx, key []byte, m Message) error {
	enc, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketMessages).Put(key, enc)
}
