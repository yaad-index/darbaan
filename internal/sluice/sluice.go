package sluice

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/audit"
	"github.com/yaad-index/darbaan/internal/seqkey"
)

// bucketMessages holds the pending outbound messages, keyed by big-endian
// sequence so a cursor iterates them in receive order.
var bucketMessages = []byte("messages")

// ErrNotFound is returned by Get when no message has the given id.
var ErrNotFound = errors.New("sluice: message not found")

// ErrNotPending is returned when a verdict is applied to a message that is no
// longer pending (already approved or rejected) — fail-closed against double
// decisions.
var ErrNotPending = errors.New("sluice: message is not pending")

// Status is the disposition of a queued message. New messages are Pending;
// the approval pipeline transitions them to Approved or Rejected. Default-deny
// means nothing leaves on Approved either until a real Sender is wired
// (ADR 0003) — Approved records the verdict, it does not imply "sent".
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

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

	// Set on a terminal transition (approved/rejected):
	DecidedBy string `json:"decided_by,omitempty"` // approver that decided
	Reason    string `json:"reason,omitempty"`     // rejection reason
	Retryable bool   `json:"retryable,omitempty"`  // rejection: transient vs permanent
	Released  []byte `json:"released,omitempty"`   // edited body approved instead of Raw (ADR 0004); nil = original
	SendErr   string `json:"send_err,omitempty"`   // result of the last send attempt (e.g. "upstream send pending")
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
		if err := b.Put(seqkey.Encode(seq), enc); err != nil {
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

// Approve marks a pending message approved, recording the deciding approver and
// (when edited) the released body, plus a hash-chained audit entry — all in one
// transaction. It does NOT send: releasing upstream is a separate, stubbed seam,
// so default-deny stays structural (ADR 0003). Approving a non-pending message
// returns ErrNotPending.
func (s *Sluice) Approve(id, decidedBy string, released []byte) (Message, error) {
	return s.transitionFromPending(id, "approve", decidedBy, func(m *Message) {
		m.Status = StatusApproved
		m.DecidedBy = decidedBy
		if released != nil && !bytes.Equal(released, m.Raw) {
			m.Released = released
		}
	})
}

// Reject marks a pending message rejected with a reason and retryable flag, plus
// a hash-chained audit entry, in one transaction. Rejecting a non-pending
// message returns ErrNotPending.
func (s *Sluice) Reject(id, decidedBy, reason string, retryable bool) (Message, error) {
	return s.transitionFromPending(id, "reject", reason, func(m *Message) {
		m.Status = StatusRejected
		m.DecidedBy = decidedBy
		m.Reason = reason
		m.Retryable = retryable
	})
}

// RecordSendAttempt records the result of attempting to release an approved
// message to the upstream Sender, with an audit entry. While the Sender is
// stubbed this always records the pending-send error; the message is never
// quietly dropped (ADR 0003).
func (s *Sluice) RecordSendAttempt(id string, sendErr error) (Message, error) {
	var out Message
	err := s.db.Update(func(tx *bbolt.Tx) error {
		m, key, err := loadMessage(tx, id)
		if err != nil {
			return err
		}
		detail := "sent"
		if sendErr != nil {
			detail = sendErr.Error()
			m.SendErr = sendErr.Error()
		}
		if err := putMessage(tx, key, m); err != nil {
			return err
		}
		if _, err := audit.Append(tx, audit.Record{
			Event: "send_attempt", Agent: m.Agent, MessageID: id, Detail: detail,
		}); err != nil {
			return err
		}
		out = m
		return nil
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: record send attempt: %w", err)
	}
	return out, nil
}

// transitionFromPending loads a pending message, applies mutate, stores it, and
// appends an audit entry (event, with detail) — atomically. It errors if the
// message is not pending, so a verdict can never be applied twice.
func (s *Sluice) transitionFromPending(id, event, detail string, mutate func(*Message)) (Message, error) {
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
		if err := putMessage(tx, key, m); err != nil {
			return err
		}
		if _, err := audit.Append(tx, audit.Record{
			Event: event, Agent: m.Agent, MessageID: id, Detail: detail,
		}); err != nil {
			return err
		}
		out = m
		return nil
	})
	if err != nil {
		return Message{}, fmt.Errorf("sluice: %s: %w", event, err)
	}
	return out, nil
}

// VerifyAudit walks the audit chain and reports the first inconsistency, if any.
func (s *Sluice) VerifyAudit() error {
	return s.db.View(func(tx *bbolt.Tx) error {
		return audit.Verify(tx)
	})
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
