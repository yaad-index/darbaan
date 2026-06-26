package telegram_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/telegram"
)

func TestNewValidation(t *testing.T) {
	ac := admin.NewClient("127.0.0.1:1144", "admintoken")

	_, err := telegram.New("", 12345, time.Second, ac)
	require.Error(t, err) // empty bot token

	_, err = telegram.New("123:bot-token", 0, time.Second, ac)
	require.Error(t, err) // no operator id

	_, err = telegram.New("123:bot-token", 12345, time.Second, nil)
	require.Error(t, err) // no admin client
}

func TestNewSucceedsWithoutNetwork(t *testing.T) {
	// WithSkipGetMe means construction does not call the Telegram API; the
	// connect happens in Run.
	c, err := telegram.New("123:fake-token", 12345, 0, admin.NewClient("127.0.0.1:1144", "tok"))
	require.NoError(t, err)
	assert.NotNil(t, c)
}
