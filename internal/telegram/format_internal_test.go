package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
	"github.com/yaad-index/darbaan/internal/sluice"
)

func TestFormatPending(t *testing.T) {
	m := sluice.Meta{ID: "7", From: "a@x.test", Rcpt: []string{"b@y.test", "c@y.test"}, Subject: "deploy keys", Size: 2048}
	out := formatPending(m)
	assert.Contains(t, out, "id: 7")
	assert.Contains(t, out, "from: a@x.test")
	assert.Contains(t, out, "to: b@y.test, c@y.test")
	assert.Contains(t, out, "subject: deploy keys")
	assert.Contains(t, out, "size: 2048 bytes")

	// An empty subject reads as "(no subject)", never blank.
	assert.Contains(t, formatPending(sluice.Meta{ID: "8", Subject: "  "}), "subject: (no subject)")
}

func TestDecisionKeyboard(t *testing.T) {
	kb := decisionKeyboard("42")
	var labels, data []string
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			labels = append(labels, b.Text)
			data = append(data, b.CallbackData)
		}
	}
	// All three decision buttons, each carrying its action + the message id.
	assert.Len(t, labels, 3)
	assert.Equal(t, []string{"approve:42", "reject_perm:42", "reject_retry:42"}, data)
	assert.Contains(t, strings.Join(labels, "|"), "Approve")
}

func TestDecisionResult(t *testing.T) {
	assert.Equal(t, "Approved 7 — approved and sent upstream",
		decisionResult("Approved", "7", admin.Outcome{Detail: "approved and sent upstream"}, nil))
	assert.Contains(t,
		decisionResult("Approved", "7", admin.Outcome{Detail: "approved", Warn: "send failed permanently"}, nil),
		"[warning: send failed permanently]")
	assert.Contains(t,
		decisionResult("Approved", "7", admin.Outcome{}, errors.New("message is rejected, not pending")),
		"failed (7): message is rejected")
}

func TestIsOperatorGate(t *testing.T) {
	c, err := New("123:fake", 999, 0, admin.NewClient("127.0.0.1:1144", "t"))
	require.NoError(t, err)
	assert.True(t, c.isOperator(&models.CallbackQuery{From: models.User{ID: 999}}))
	assert.False(t, c.isOperator(&models.CallbackQuery{From: models.User{ID: 111}})) // not the operator
	assert.False(t, c.isOperator(nil))
}

func TestIsReply(t *testing.T) {
	assert.True(t, isReply(&models.Update{Message: &models.Message{ReplyToMessage: &models.Message{ID: 1}}}))
	assert.False(t, isReply(&models.Update{Message: &models.Message{}})) // not a reply
	assert.False(t, isReply(&models.Update{}))                           // no message
}

// A reason reply is acted on only when it's from the operator AND replies to a
// prompt we sent. The other paths must return before any admin/Telegram call,
// leaving the pending entry intact.
func TestHandleReasonReplyGate(t *testing.T) {
	c, err := New("123:fake", 999, 0, admin.NewClient("127.0.0.1:1", "t"))
	require.NoError(t, err)
	c.pending[55] = rejectState{id: "7"}

	c.handleReasonReply(context.Background(), c.bot, &models.Update{Message: &models.Message{
		From: &models.User{ID: 111}, ReplyToMessage: &models.Message{ID: 55}, Text: "x", // not the operator
	}})
	assert.Contains(t, c.pending, 55)

	c.handleReasonReply(context.Background(), c.bot, &models.Update{Message: &models.Message{
		From: &models.User{ID: 999}, ReplyToMessage: &models.Message{ID: 4242}, Text: "x", // unknown prompt
	}})
	assert.Contains(t, c.pending, 55)
}
