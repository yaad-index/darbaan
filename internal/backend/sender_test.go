package backend_test

import (
	"context"
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func TestStubSenderNeverSends(t *testing.T) {
	err := backend.StubSender{}.Send(context.Background(), sluice.Message{ID: "1"})
	assert.ErrorIs(t, err, backend.ErrSendPending)
}

func TestNewDefaultsToStub(t *testing.T) {
	s, err := backend.New("stub", backend.Config{})
	require.NoError(t, err)
	assert.ErrorIs(t, s.Send(context.Background(), sluice.Message{}), backend.ErrSendPending)
	assert.Contains(t, backend.Registered(), "stub")
	assert.Contains(t, backend.Registered(), "smtp")
}

func TestNewUnknownType(t *testing.T) {
	_, err := backend.New("carrier-pigeon", backend.Config{})
	require.Error(t, err)
}

func TestSMTPRequiresHostAndCreds(t *testing.T) {
	// Fail closed: smtp without host/username/password is not constructible.
	_, err := backend.New("smtp", backend.Config{})
	require.Error(t, err)
	_, err = backend.New("smtp", backend.Config{Host: "smtp.gmail.com:587", Username: "u"})
	require.Error(t, err) // missing password
	_, err = backend.New("smtp", backend.Config{Host: "no-port", Username: "u", Password: "p"})
	require.Error(t, err) // host must be host:port
}

func TestIsPermanent(t *testing.T) {
	assert.True(t, backend.IsPermanent(&smtp.SMTPError{Code: 550}))
	assert.True(t, backend.IsPermanent(&smtp.SMTPError{Code: 500}))
	assert.False(t, backend.IsPermanent(&smtp.SMTPError{Code: 451})) // transient
	assert.False(t, backend.IsPermanent(errors.New("dial tcp: connection refused")))
	assert.False(t, backend.IsPermanent(backend.ErrSendPending))
	assert.False(t, backend.IsPermanent(nil))
}
