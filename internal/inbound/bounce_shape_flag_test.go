package inbound_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
)

// A multipart/report DSN whose From is an ordinary address: bounce-shaped, but
// invisible to the metadata-only From pre-check. This is the population the stored
// flag exists for (#127).
const dsnNonDaemon = "Content-Type: multipart/report; report-type=\"delivery-status\"; boundary=\"b\"\r\n" +
	"From: notifications@service.example\r\nSubject: Delivery Status Notification\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\n\r\nbounced\r\n" +
	"--b\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822;x@y.test\r\nAction: failed\r\n" +
	"--b--\r\n"

const ordinaryMail = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: lunch?\r\n\r\nhey\r\n"

// 🚨 A record with no body written has a NIL flag, not false. nil means nothing has
// looked; false would assert "this is not a bounce" about a message nothing has
// examined, stored in the place a later reader trusts most.
func TestPendingRecordHasNoShapeClaim(t *testing.T) {
	s := newStore(t)
	_, pending, err := s.AddSyncedPending(inbound.Delivery{
		Owner: "agent", UpstreamUID: 1, UIDValidity: 1, Subject: "unfetched",
	})
	require.NoError(t, err)
	assert.Nil(t, pending.BounceShaped, "no body written yet, so no claim about its shape")

	got, err := s.Get("agent", inbound.DefaultInbox, pending.ID)
	require.NoError(t, err)
	assert.Nil(t, got.BounceShaped, "and the absence of a claim survives a read")
}

// Filling the body computes the flag, in the same write that stores the content —
// so a present record can never carry an unknown shape.
func TestSetContentComputesTheShapeFlag(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"non-daemon DSN": {dsnNonDaemon, true},
		"ordinary mail":  {ordinaryMail, false},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			_, pending, err := s.AddSyncedPending(inbound.Delivery{
				Owner: "agent", UpstreamUID: 1, UIDValidity: 1,
			})
			require.NoError(t, err)
			require.Nil(t, pending.BounceShaped, "control: unknown before the body arrives")

			full, err := s.SetContent("agent", inbound.DefaultInbox, pending.ID, []byte(tc.raw))
			require.NoError(t, err)
			require.NotNil(t, full.BounceShaped, "the body is written, so the shape is now known")
			assert.Equal(t, tc.want, *full.BounceShaped)

			got, err := s.Get("agent", inbound.DefaultInbox, pending.ID)
			require.NoError(t, err)
			require.NotNil(t, got.BounceShaped, "and it persisted")
			assert.Equal(t, tc.want, *got.BounceShaped)
		})
	}
}

// A message added with its body present is known at insert, via the same chokepoint.
func TestPresentAddComputesTheShapeFlag(t *testing.T) {
	s := newStore(t)
	m, err := s.Add(inbound.Delivery{
		Owner: "agent", From: "notifications@service.example", Subject: "DSN",
		Raw: []byte(dsnNonDaemon),
	})
	require.NoError(t, err)
	require.NotNil(t, m.BounceShaped)
	assert.True(t, *m.BounceShaped)
}

// 🔑 The flag has to survive the metadata-only listing, because that listing is
// exactly where there is no body to check and where the guard reads it. List
// deliberately nils Raw; it must NOT nil this.
func TestShapeFlagSurvivesTheMetadataOnlyListing(t *testing.T) {
	s := newStore(t)
	_, pending, err := s.AddSyncedPending(inbound.Delivery{Owner: "agent", UpstreamUID: 1, UIDValidity: 1})
	require.NoError(t, err)
	_, err = s.SetContent("agent", inbound.DefaultInbox, pending.ID, []byte(dsnNonDaemon))
	require.NoError(t, err)

	listed, err := s.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Empty(t, listed[0].Raw, "control: the listing is metadata-only, as ADR 0019 requires")
	require.NotNil(t, listed[0].BounceShaped, "but the shape claim must reach the guard, which runs here")
	assert.True(t, *listed[0].BounceShaped)
}
