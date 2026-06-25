package sluice

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/audit"
)

// bucketMessages holds the pending outbound messages, keyed by big-endian
// sequence so a cursor iterates them in receive order.
var bucketMessages = []byte("messages")

// ErrNotFound is returned by Get when no message has the given id.
var ErrNotFound = errors.New("sluice: message not found")

// Status is the disposition of a queued message. v1 only ever holds Pending:
// the sluice is default-deny and nothing is released without an approval pass
// (ADR 0003), which lands in a later component.
type Status string

const StatusPending Status = "pending"

// Submission is a new outbound message to trap, as captured from the SMTP face.
type Submission struct {
	Agent string   // authenticated agent identity (ADR 0002)
	From  string   // envelope MAIL FROM
	Rcpt  []string // envelope RCPT TO
	Raw   []byte   // raw message/rfc822
}

// Message is a trapped outbound submission held in the sluice.
type Message struct {
	ID         string    `json:"id"`
	Agent      string    `json:"agent"`
	From       string    `json:"from"`
	Rcpt       []string  `json:"rcpt"`
	Raw        []byte    `json:"raw"`
	ReceivedAt time.Time `json:"received_at"`
	Status     Status    `json:"status"`
}

// Meta is the listing view of a queued message: everything but the raw body.
type Meta struct {
	ID         string
	Agent      string
	From       string
	Rcpt       []string
	Size       int
	ReceivedAt time.Time
	Status     Status
}

// Sluice is the durable, append-only outbound hold/queue (ADR 0003), backed by
// a single bbolt file so enqueue and its audit entry commit atomically.
type Sluice struct {
	db *bbolt.DB
}

// Open opens (creating if needed) the sluice database at path.
func Open(path string) (*Sluice, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("sluice: open db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketMessages); err != nil {
			return err
		}
		return audit.EnsureBucket(tx)
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sluice: init buckets: %w", err)
	}
	return &Sluice{db: db}, nil
}

// Close releases the database file lock.
func (s *Sluice) Close() error { return s.db.Close() }

// Enqueue durably traps a submission as a pending message and records a
// hash-chained audit entry in the same transaction. Nothing is sent upstream
// — the sluice only holds (ADR 0003).
func (s *Sluice) Enqueue(sub Submission) (Message, error) {
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
		if err := b.Put(itob(seq), enc); err != nil {
			return err
		}
		_, err = audit.Append(tx, audit.Record{
			Event:     "enqueue",
			Agent:     msg.Agent,
			MessageID: msg.ID,
		})
		return err
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: enqueue: %w", err)
	}
	return msg, nil
}

// List returns the metadata of every queued message in receive order.
func (s *Sluice) List() ([]Meta, error) {
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

// Get returns the full message (including the raw body) for id, or ErrNotFound.
func (s *Sluice) Get(id string) (Message, error) {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Message{}, fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	var msg Message
	err = s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketMessages).Get(itob(seq))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &msg)
	})
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

// VerifyAudit walks the audit chain and reports the first inconsistency, if any.
func (s *Sluice) VerifyAudit() error {
	return s.db.View(func(tx *bbolt.Tx) error {
		return audit.Verify(tx)
	})
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
