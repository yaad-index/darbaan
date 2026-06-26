package telegram

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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
