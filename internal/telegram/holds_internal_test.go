package telegram

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/inbound"
)

func TestFormatHold(t *testing.T) {
	s := formatHold(inbound.Message{ID: "7", From: "a@x.test", To: "b@y.test", Subject: "hello"})
	assert.Contains(t, s, "expose to the agent?")
	assert.Contains(t, s, "id: 7")
	assert.Contains(t, s, "from: a@x.test")
	assert.Contains(t, s, "to: b@y.test")
	assert.Contains(t, s, "subject: hello")
	assert.Contains(t, formatHold(inbound.Message{ID: "8"}), "(no subject)")
}

func TestHoldKeyboard(t *testing.T) {
	kb := holdKeyboard("7")
	var data []string
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			data = append(data, btn.CallbackData)
		}
	}
	assert.Contains(t, data, cbExpose+"7")
	assert.Contains(t, data, cbDrop+"7")
}

func TestHoldResult(t *testing.T) {
	assert.Contains(t, holdResult("Exposed", "7", nil), "visible to the agent")
	assert.Contains(t, holdResult("Dropped", "7", nil), "stays hidden")
	assert.True(t, strings.Contains(holdResult("Exposed", "7", errors.New("boom")), "failed"))
}

func TestPostedHoldsDedup(t *testing.T) {
	c := &Client{postedHolds: map[string]bool{}}
	assert.False(t, c.seenHold("1"))
	c.markPostedHold("1")
	c.markPostedHold("2")
	assert.True(t, c.seenHold("1"))

	// Prune drops entries no longer in the live held queue.
	c.prunePostedHolds([]inbound.Message{{ID: "1"}})
	assert.True(t, c.seenHold("1"))
	assert.False(t, c.seenHold("2"))
}
