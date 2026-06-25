package approver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/approver"
)

func TestRegistryNewAndList(t *testing.T) {
	approver.Register("test-reg", func() approver.Approver { return approve("test-reg") })

	a, err := approver.New("test-reg")
	require.NoError(t, err)
	assert.Equal(t, "test-reg", a.Name())
	assert.Contains(t, approver.Registered(), "test-reg")
}

func TestRegistryUnknownErrors(t *testing.T) {
	_, err := approver.New("nope-not-compiled-in")
	require.Error(t, err)
}

func TestRegistryDuplicatePanics(t *testing.T) {
	approver.Register("test-dup", func() approver.Approver { return approve("test-dup") })
	assert.Panics(t, func() {
		approver.Register("test-dup", func() approver.Approver { return approve("test-dup") })
	})
}
