// Package imapsync pulls an upstream IMAP mailbox into Darbaan's inbound store
// (ADR 0019): store-canonical, incremental, read-only on the upstream, no
// filter (v1). It is the sync engine only — config + the serve poll loop wire it
// up separately. The agent reads the synced mail through Darbaan's IMAP read
// face, never the provider directly (ADR 0001/0002).
package imapsync

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// State is the per-mailbox sync cursor: the upstream UIDVALIDITY this cursor is
// valid for, and the highest UID synced so far. A UIDVALIDITY change invalidates
// LastUID and forces a re-sync (ADR 0019).
type State struct {
	UIDValidity uint32 `json:"uid_validity"`
	LastUID     uint32 `json:"last_uid"`
}

// StateStore persists the sync cursor per mailbox.
type StateStore interface {
	Load(mailbox string) (State, error)
	Save(mailbox string, st State) error
	Close() error
}

var bucketSyncState = []byte("syncstate")

type bboltState struct{ db *bbolt.DB }

// NewStateStore opens (or creates) a small bbolt store for sync cursors.
func NewStateStore(path string) (StateStore, error) {
	if path == "" {
		return nil, fmt.Errorf("imapsync: state store requires a path")
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("imapsync: open state db: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketSyncState)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("imapsync: init state bucket: %w", err)
	}
	return &bboltState{db: db}, nil
}

func (s *bboltState) Close() error { return s.db.Close() }

// Load returns the cursor for a mailbox, or the zero State if none is recorded.
func (s *bboltState) Load(mailbox string) (State, error) {
	var st State
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketSyncState).Get([]byte(mailbox))
		if v == nil {
			return nil // zero State — never synced
		}
		return json.Unmarshal(v, &st)
	})
	if err != nil {
		return State{}, fmt.Errorf("imapsync: load state %q: %w", mailbox, err)
	}
	return st, nil
}

func (s *bboltState) Save(mailbox string, st State) error {
	enc, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSyncState).Put([]byte(mailbox), enc)
	}); err != nil {
		return fmt.Errorf("imapsync: save state %q: %w", mailbox, err)
	}
	return nil
}
