package inbound

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"go.etcd.io/bbolt"

	"github.com/yaad-index/darbaan/internal/seqkey"
)

var bucketInbound = []byte("inbound")

func init() {
	Register("bbolt", newBbolt)
}

// bboltStore is the bbolt-backed InboundStore, in its own database.
type bboltStore struct{ db *bbolt.DB }

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
	return &bboltStore{db: db}, nil
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
		enc, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return b.Put(seqkey.Encode(seq), enc)
	})
	if err != nil {
		return Message{}, fmt.Errorf("inbound: add: %w", err)
	}
	return msg, nil
}

func (s *bboltStore) List(owner string) ([]Message, error) {
	var out []Message
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInbound).ForEach(func(_, v []byte) error {
			var m Message
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			if m.Owner == owner {
				out = append(out, m)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("inbound: list: %w", err)
	}
	return out, nil
}

func (s *bboltStore) SetSeen(owner, id string, seen bool) error {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	key := seqkey.Encode(seq)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketInbound)
		v := b.Get(key)
		if v == nil {
			return ErrNotFound
		}
		var m Message
		if err := json.Unmarshal(v, &m); err != nil {
			return err
		}
		if m.Owner != owner {
			return ErrNotFound // do not touch another owner's message
		}
		if m.Seen == seen {
			return nil
		}
		m.Seen = seen
		enc, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return b.Put(key, enc)
	})
}

func (s *bboltStore) Get(owner, id string) (Message, error) {
	seq, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Message{}, fmt.Errorf("%w: invalid id %q", ErrNotFound, id)
	}
	var msg Message
	err = s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketInbound).Get(seqkey.Encode(seq))
		if v == nil {
			return ErrNotFound
		}
		if err := json.Unmarshal(v, &msg); err != nil {
			return err
		}
		if msg.Owner != owner {
			return ErrNotFound // do not leak another owner's message
		}
		return nil
	})
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}
