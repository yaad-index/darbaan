package backend_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func TestStubSenderNeverSends(t *testing.T) {
	err := backend.StubSender{}.Send(context.Background(), sluice.Message{ID: "1"})
	assert.ErrorIs(t, err, backend.ErrSendPending)
}
