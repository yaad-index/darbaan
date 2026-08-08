package inbound_test

import (
	"testing"

	"github.com/yaad-index/darbaan/internal/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetContentAssessedPersists(t *testing.T) {
	s := newStore(t)
	_, m, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)

	a := &inbound.Assessment{
		Disposition: inbound.AssessmentHeld, Score: 80, Band: "high",
		Factors: []string{"instruction_to_reader"}, Summary: "flagged",
	}
	filled, err := s.SetContentAssessed("agent", inbound.DefaultInbox, m.ID, []byte("Subject: x\r\n\r\nbody"), a)
	require.NoError(t, err)
	require.NotNil(t, filled.Assessment)
	assert.Equal(t, inbound.AssessmentHeld, filled.Assessment.Disposition)
	assert.True(t, filled.HeldByAssessment())

	got, err := s.Get("agent", inbound.DefaultInbox, m.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Assessment, "assessment persists across a reload")
	assert.Equal(t, 80, got.Assessment.Score)
	assert.True(t, got.HeldByAssessment())
}

// A nil assessment is exactly SetContent: the message is not assessed and never
// held (old records and flag-off messages are untouched).
func TestSetContentNilAssessmentNotHeld(t *testing.T) {
	s := newStore(t)
	_, m, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)

	filled, err := s.SetContentAssessed("agent", inbound.DefaultInbox, m.ID, []byte("Subject: x\r\n\r\nbody"), nil)
	require.NoError(t, err)
	assert.Nil(t, filled.Assessment)
	assert.False(t, filled.HeldByAssessment())

	// SetContent is the same path.
	_, m2, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 2, UIDValidity: 1})
	require.NoError(t, err)
	plain, err := s.SetContent("agent", inbound.DefaultInbox, m2.ID, []byte("Subject: y\r\n\r\nbody"))
	require.NoError(t, err)
	assert.Nil(t, plain.Assessment)
}

func TestHeldByAssessment(t *testing.T) {
	assert.False(t, inbound.Message{}.HeldByAssessment(), "nil assessment is never held")
	assert.True(t, inbound.Message{Assessment: &inbound.Assessment{Disposition: inbound.AssessmentHeld}}.HeldByAssessment())
	assert.False(t, inbound.Message{Assessment: &inbound.Assessment{Disposition: inbound.AssessmentAgentHandled}}.HeldByAssessment())
}
