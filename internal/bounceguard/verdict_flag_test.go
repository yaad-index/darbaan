package bounceguard_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/bounceguard"
)

// 🚨 The population the guard structurally could not see before #127, and which no
// existing fixture contained: a multipart/report DSN whose From is an ordinary
// address. Shaped() catches it, Candidate() cannot — so at a metadata-only listing
// nothing triggered the check.
const dsnNonDaemonFrom = "Content-Type: multipart/report; report-type=\"delivery-status\"; boundary=\"b\"\r\n" +
	"From: notifications@service.example\r\nSubject: Delivery Status Notification\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\n\r\nyour message bounced\r\n" +
	"--b\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822;x@y.test\r\nAction: failed\r\n" +
	"--b--\r\n"

func neverSigned() *bounceguard.Guard {
	return bounceguard.New(func([]byte) (bool, error) { return false, nil })
}

func ptr(b bool) *bool { return &b }

// The fixture itself must disagree with the pre-check, or every assertion below is
// about something else.
func TestNonDaemonDSNIsShapedButNotACandidate(t *testing.T) {
	require.True(t, bounceguard.Shaped([]byte(dsnNonDaemonFrom)),
		"fixture must be bounce-shaped, or it is not the case #127 is about")
	require.False(t, bounceguard.Candidate([]string{"notifications"}),
		"and must NOT be reachable by the From pre-check, which is why the flag exists")
}

// A true flag triggers the fetch and the full check where the pre-check cannot.
func TestVerdictFlagCatchesNonDaemonDSN(t *testing.T) {
	fetched := false
	spoof, err := neverSigned().Verdict([]string{"notifications"}, ptr(true), nil, func() ([]byte, error) {
		fetched = true
		return []byte(dsnNonDaemonFrom), nil
	})
	require.NoError(t, err)
	assert.True(t, fetched, "a shape-flagged message is fetched so it can be verified")
	assert.True(t, spoof, "bounce-shaped and unsigned is a spoof (ADR 0024)")
}

// 🔑 The property that makes the flag safe to add: it is ADDITIVE ONLY. A false flag
// must not suppress the From pre-check, because a stored flag is a cache of a past
// read and a cache that can SUPPRESS a check could hide a spoof if it were ever
// stale or mis-written. This is the case a plain if/else would have broken.
func TestVerdictFalseFlagDoesNotSuppressTheFromPrecheck(t *testing.T) {
	fetched := false
	spoof, err := neverSigned().Verdict([]string{"MAILER-DAEMON"}, ptr(false), nil, func() ([]byte, error) {
		fetched = true
		return []byte(dsnNonDaemonFrom), nil
	})
	require.NoError(t, err)
	assert.True(t, fetched, "a daemon-like From still triggers the check regardless of the flag")
	assert.True(t, spoof)
}

// A false flag on a message the pre-check also cannot see costs no fetch — the body
// has been examined and is not bounce-shaped, which IS evidence, unlike nil.
func TestVerdictFalseFlagAndNoCandidateSkipsTheFetch(t *testing.T) {
	fetched := false
	spoof, err := neverSigned().Verdict([]string{"alice"}, ptr(false), nil, func() ([]byte, error) {
		fetched = true
		return []byte(dsnNonDaemonFrom), nil
	})
	require.NoError(t, err)
	assert.False(t, fetched, "examined and not bounce-shaped: nothing to verify")
	assert.False(t, spoof)
}

// nil is not evidence, so behaviour is exactly what it was before the flag existed.
// Both halves asserted, since "unchanged" is a claim about two cases and not one.
func TestVerdictNilFlagIsPreFlagBehaviour(t *testing.T) {
	t.Run("no candidate: no fetch, not spoof", func(t *testing.T) {
		fetched := false
		spoof, err := neverSigned().Verdict([]string{"notifications"}, nil, nil, func() ([]byte, error) {
			fetched = true
			return []byte(dsnNonDaemonFrom), nil
		})
		require.NoError(t, err)
		assert.False(t, fetched, "nothing has examined this message, so nothing is claimed about it")
		assert.False(t, spoof)
	})
	t.Run("candidate: fetch and check", func(t *testing.T) {
		fetched := false
		spoof, err := neverSigned().Verdict([]string{"postmaster"}, nil, nil, func() ([]byte, error) {
			fetched = true
			return []byte(dsnNonDaemonFrom), nil
		})
		require.NoError(t, err)
		assert.True(t, fetched)
		assert.True(t, spoof)
	})
}

// A shape-flagged message whose body cannot be fetched is fail-CLOSED, matching the
// Candidate path: bounce-shaped and unverifiable is a spoof.
func TestVerdictFlaggedFetchFailureIsFailClosed(t *testing.T) {
	boom := errors.New("upstream gone")
	spoof, err := neverSigned().Verdict([]string{"notifications"}, ptr(true), nil, func() ([]byte, error) {
		return nil, boom
	})
	require.ErrorIs(t, err, boom)
	assert.True(t, spoof, "shape-flagged and unverifiable must not be surfaced")
}

// Raw already in hand short-circuits everything: the full check runs on the real
// bytes and the flag is not consulted, even when it disagrees with them.
func TestVerdictRawInHandIgnoresTheFlag(t *testing.T) {
	spoof, err := neverSigned().Verdict([]string{"alice"}, ptr(false), []byte(dsnNonDaemonFrom), func() ([]byte, error) {
		t.Fatal("must not fetch when raw is in hand")
		return nil, nil
	})
	require.NoError(t, err)
	assert.True(t, spoof, "the bytes win over a flag that contradicts them")
}
