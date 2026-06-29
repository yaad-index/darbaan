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
