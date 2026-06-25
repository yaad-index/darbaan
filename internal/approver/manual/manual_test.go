package manual_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/approver/manual"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func TestManualRegistersAndDefaultsHold(t *testing.T) {
	a, err := approver.New(manual.Name)
	require.NoError(t, err)
	assert.True(t, a.CanEdit())

	// A constructed-but-unset manual approver returns Hold — fail-closed.
	v, err := a.Decide(context.Background(), sluice.Message{})
	require.NoError(t, err)
	assert.Equal(t, approver.Hold, v.Disposition)
}

func TestManualReturnsSetVerdict(t *testing.T) {
	m := manual.New(approver.Verdict{Disposition: approver.Approve})
	v, err := m.Decide(context.Background(), sluice.Message{})
	require.NoError(t, err)
	assert.Equal(t, approver.Approve, v.Disposition)

	m.SetVerdict(approver.Verdict{Disposition: approver.Reject, Reason: "no"})
	v, err = m.Decide(context.Background(), sluice.Message{})
	require.NoError(t, err)
	assert.Equal(t, approver.Reject, v.Disposition)
	assert.Equal(t, "no", v.Reason)
}
