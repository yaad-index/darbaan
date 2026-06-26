// Package blobstore is a small filesystem blob store: one file per key under a
// directory. It backs the content tier of the message stores (ADR 0018) — the
// raw RFC 822 bytes live here, keyed by message id, while bbolt holds only
// metadata + a reference.
//
// Put writes durably (temp file, fsync, atomic rename, dir fsync) so the blob is
// on disk before the caller commits the referencing metadata. With that
// ordering a metadata record never points to missing content; a crash can only
// leave a reclaimable orphan blob.
package blobstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Store writes and reads blobs under a single directory.
type Store struct {
	dir string
}

// New creates (if needed) and opens the blob directory.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("blobstore: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("blobstore: mkdir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(key string) string { return filepath.Join(s.dir, key) }

// Put writes the blob for key durably. It is the first half of the
// blob-then-metadata write order: when Put returns, the bytes are on disk.
func (s *Store) Put(key string, data []byte) error {
	if err := validKey(key); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, key+".tmp-*")
	if err != nil {
		return fmt.Errorf("blobstore: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blobstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blobstore: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("blobstore: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path(key)); err != nil {
		return fmt.Errorf("blobstore: rename: %w", err)
	}
	return syncDir(s.dir)
}

// Get reads the blob for key.
func (s *Store) Get(key string) ([]byte, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return nil, fmt.Errorf("blobstore: read %s: %w", key, err)
	}
	return data, nil
}

// Delete removes the blob for key. A missing blob is not an error (idempotent).
func (s *Store) Delete(key string) error {
	if err := validKey(key); err != nil {
		return err
	}
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blobstore: delete %s: %w", key, err)
	}
	return nil
}

// validKey keeps a key to a single path element — it can never contain a
// separator or traverse out of the directory (defense in depth; ids are
// store-generated, never operator input).
func validKey(key string) error {
	if key == "" || key == "." || key == ".." || strings.ContainsAny(key, `/\`) {
		return fmt.Errorf("blobstore: invalid key %q", key)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("blobstore: open dir for fsync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("blobstore: fsync dir: %w", err)
	}
	return nil
}
