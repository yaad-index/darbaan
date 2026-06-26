package blobstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/blobstore"
)

func TestPutGetDelete(t *testing.T) {
	s, err := blobstore.New(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, s.Put("1", []byte("hello")))
	got, err := s.Get("1")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)

	require.NoError(t, s.Delete("1"))
	require.NoError(t, s.Delete("1")) // missing blob is not an error
	_, err = s.Get("1")
	assert.Error(t, err)
}

func TestPutOverwrites(t *testing.T) {
	s, err := blobstore.New(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, s.Put("1", []byte("old")))
	require.NoError(t, s.Put("1", []byte("new")))
	got, err := s.Get("1")
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestSweepOrphans(t *testing.T) {
	dir := t.TempDir()
	s, err := blobstore.New(dir)
	require.NoError(t, err)
	require.NoError(t, s.Put("1", []byte("live")))
	require.NoError(t, s.Put("2", []byte("orphan")))
	require.NoError(t, s.Put("3", []byte("live")))
	// An interrupted Put leaves a temp file; the sweep must skip it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "9.tmp-abc123"), []byte("partial"), 0o600))

	n, err := s.SweepOrphans(map[string]bool{"1": true, "3": true})
	require.NoError(t, err)
	assert.Equal(t, 1, n) // only "2" had no referencing metadata

	_, err = s.Get("2")
	assert.Error(t, err) // reclaimed
	got, err := s.Get("1")
	require.NoError(t, err)
	assert.Equal(t, []byte("live"), got) // referenced blob kept
	_, err = os.Stat(filepath.Join(dir, "9.tmp-abc123"))
	assert.NoError(t, err) // temp file untouched
}

func TestInvalidKeyRejectsTraversal(t *testing.T) {
	s, err := blobstore.New(t.TempDir())
	require.NoError(t, err)
	for _, k := range []string{"", ".", "..", "a/b", `a\b`, "../escape"} {
		assert.Error(t, s.Put(k, []byte("x")), "key %q must be rejected", k)
	}
}
