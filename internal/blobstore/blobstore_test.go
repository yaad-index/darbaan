package blobstore_test

import (
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

func TestInvalidKeyRejectsTraversal(t *testing.T) {
	s, err := blobstore.New(t.TempDir())
	require.NoError(t, err)
	for _, k := range []string{"", ".", "..", "a/b", `a\b`, "../escape"} {
		assert.Error(t, s.Put(k, []byte("x")), "key %q must be rejected", k)
	}
}
