package bounceguard_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/bounceguard"
)

const dsnReport = "Content-Type: multipart/report; report-type=\"delivery-status\"; boundary=\"b\"\r\n" +
	"From: MAILER-DAEMON@mail.example\r\nSubject: Returned mail\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\n\r\nyour message bounced\r\n" +
	"--b\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: rfc822;x@y.test\r\nAction: failed\r\n" +
	"--b--\r\n"

func TestShaped(t *testing.T) {
	shaped := map[string]string{
		"multipart/report dsn":         dsnReport,
		"message/delivery-status leaf": "Content-Type: message/delivery-status\r\nFrom: x@y.test\r\n\r\nstatus\r\n",
		"mailer-daemon From":           "From: Mail Delivery Subsystem <MAILER-DAEMON@mail.example>\r\nSubject: x\r\n\r\nb\r\n",
		"postmaster From":              "From: postmaster@mail.example\r\nSubject: x\r\n\r\nb\r\n",
		"null sender Return-Path":      "Return-Path: <>\r\nFrom: whoever@x.test\r\nSubject: x\r\n\r\nb\r\n",
		"auto-replied + dsn ct":        "Content-Type: message/delivery-status\r\nAuto-Submitted: auto-replied\r\nFrom: a@b.test\r\n\r\ns\r\n",
	}
	for name, raw := range shaped {
		assert.True(t, bounceguard.Shaped([]byte(raw)), name)
	}

	notShaped := map[string]string{
		"ordinary mail":      "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: lunch?\r\n\r\nhey\r\n",
		"plain auto-reply":   "From: a@b.test\r\nAuto-Submitted: auto-replied\r\nSubject: OOO\r\n\r\naway\r\n", // auto-reply without DSN content type
		"postmaster in body": "From: alice@example.com\r\nSubject: hi\r\n\r\nemail postmaster@x for help\r\n",
		"unparseable":        "\x00\x01 not a message",
		"empty":              "",
	}
	for name, raw := range notShaped {
		assert.False(t, bounceguard.Shaped([]byte(raw)), name)
	}
}

func TestCandidate(t *testing.T) {
	assert.True(t, bounceguard.Candidate([]string{"MAILER-DAEMON"}))
	assert.True(t, bounceguard.Candidate([]string{"alice", "Postmaster"}))
	assert.False(t, bounceguard.Candidate([]string{"alice", "bob"}))
	assert.False(t, bounceguard.Candidate(nil))
}

func TestVerdict(t *testing.T) {
	spoofRaw := []byte(dsnReport) // shaped, and our verifier says unsigned → spoof
	unsigned := bounceguard.New(func([]byte) (bool, error) { return false, nil })

	// raw in hand → full check, no fetch needed (fetch must NOT be called)
	v, err := unsigned.Verdict(nil, spoofRaw, func() ([]byte, error) {
		t.Fatal("getRaw must not be called when raw is in hand")
		return nil, nil
	})
	assert.NoError(t, err)
	assert.True(t, v)

	// no raw, non-candidate From → pass without fetching
	fetched := false
	v, err = unsigned.Verdict([]string{"alice"}, nil, func() ([]byte, error) { fetched = true; return spoofRaw, nil })
	assert.NoError(t, err)
	assert.False(t, v)
	assert.False(t, fetched, "non-candidate must not trigger a fetch")

	// no raw, candidate From → fetch + full check → spoof
	v, err = unsigned.Verdict([]string{"MAILER-DAEMON"}, nil, func() ([]byte, error) { return spoofRaw, nil })
	assert.NoError(t, err)
	assert.True(t, v)

	// candidate but fetch fails → fail-CLOSED (true): a candidate is bounce-shaped,
	// and shaped+unverifiable is a spoof (ADR 0024); the error is surfaced for logging.
	boom := errors.New("fetch failed")
	v, err = unsigned.Verdict([]string{"postmaster"}, nil, func() ([]byte, error) { return nil, boom })
	assert.ErrorIs(t, err, boom)
	assert.True(t, v)
}

func TestIsSpoofShapeFirstThenVerify(t *testing.T) {
	ordinary := []byte("From: alice@example.com\r\nSubject: lunch?\r\n\r\nhey\r\n")

	// Ordinary mail is not bounce-shaped → verify is never called (cheap-first).
	called := false
	g := bounceguard.New(func([]byte) (bool, error) { called = true; return false, nil })
	spoof, err := g.IsSpoof(ordinary)
	assert.NoError(t, err)
	assert.False(t, spoof)
	assert.False(t, called, "verify must not run on non-bounce-shaped mail")

	// Bounce-shaped + valid signature → genuine bounce, not a spoof.
	g = bounceguard.New(func([]byte) (bool, error) { return true, nil })
	spoof, err = g.IsSpoof([]byte(dsnReport))
	assert.NoError(t, err)
	assert.False(t, spoof)

	// Bounce-shaped + unsigned/invalid → spoof.
	g = bounceguard.New(func([]byte) (bool, error) { return false, nil })
	spoof, err = g.IsSpoof([]byte(dsnReport))
	assert.NoError(t, err)
	assert.True(t, spoof)

	// Bounce-shaped + verify error → fail closed (spoof), surfacing the error.
	boom := errors.New("malformed")
	g = bounceguard.New(func([]byte) (bool, error) { return false, boom })
	spoof, err = g.IsSpoof([]byte(dsnReport))
	assert.ErrorIs(t, err, boom)
	assert.True(t, spoof)
}
