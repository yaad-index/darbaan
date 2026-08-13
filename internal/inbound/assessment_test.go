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

// #289: pin the tri-state truncation invariant. A non-nil false Truncated
// ("assessed on complete content" — explicitly NOT the legacy/unknown state) must
// survive a full persist+reload still non-nil AND still false. Both ways the
// invariant breaks — a future write path leaving the pointer nil, or a non-nil false
// failing to serialize — land on the same silent outcome: a fresh record reloaded as
// nil, which assessmentTruncated reads as "legacy" and the prose fallback renders
// identically, so nothing surfaces it.
//
// Level pinned: the STORE. This asserts through SetContentAssessed→Get — the bbolt
// encoding/json persistence path (the `stored` record) — not a bare struct marshal.
// Today the persisted record IS the struct under encoding/json with no intermediate
// representation, so struct-level and store-level coincide; that coincidence is
// exactly what this must outlive. A later DTO or custom marshaler that dropped the
// field would leave a struct-level round trip green while reintroducing the defect one
// layer up — the same silent failure the pin exists to prevent.
func TestAssessmentTruncatedFalseSurvivesStoreRoundTrip(t *testing.T) {
	s := newStore(t)
	_, m, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)

	no := false // non-nil false: the state a plain bool cannot distinguish from absent
	a := &inbound.Assessment{
		Disposition: inbound.AssessmentAgentHandled, Score: 10, Band: "low",
		Truncated: &no,
	}
	_, err = s.SetContentAssessed("agent", inbound.DefaultInbox, m.ID, []byte("Subject: x\r\n\r\nbody"), a)
	require.NoError(t, err)

	got, err := s.Get("agent", inbound.DefaultInbox, m.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Assessment)
	require.NotNil(t, got.Assessment.Truncated,
		"a non-nil false must survive persist+reload still non-nil — else a fresh not-truncated record reloads as nil and is misfiled as legacy (#289)")
	assert.False(t, *got.Assessment.Truncated,
		"and still false, so a later swap to a plain bool fails here loudly instead of silently re-entering the legacy cohort")
}

func TestHeldByAssessment(t *testing.T) {
	assert.False(t, inbound.Message{}.HeldByAssessment(), "nil assessment is never held")
	assert.True(t, inbound.Message{Assessment: &inbound.Assessment{Disposition: inbound.AssessmentHeld}}.HeldByAssessment())
	assert.False(t, inbound.Message{Assessment: &inbound.Assessment{Disposition: inbound.AssessmentAgentHandled}}.HeldByAssessment())
}
