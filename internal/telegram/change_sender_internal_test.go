package telegram

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admin"
)

func TestParseApproveAs(t *testing.T) {
	inbox, id, ok := parseApproveAs("approve_as:work:42")
	require.True(t, ok)
	assert.Equal(t, "work", inbox)
	assert.Equal(t, "42", id)

	// The id is the final ":"-separated field, so an inbox name containing ":"
	// still parses correctly.
	inbox, id, ok = parseApproveAs("approve_as:od:d:7")
	require.True(t, ok)
	assert.Equal(t, "od:d", inbox)
	assert.Equal(t, "7", id)

	_, _, ok = parseApproveAs("approve_as:noid")
	assert.False(t, ok)
}

// The identity picker offers one approve-as button per identity, plus a Back.
func TestIdentityKeyboard(t *testing.T) {
	c := &Client{identities: []admin.InboxIdentity{{Name: "work", Identity: "w@x"}, {Name: "personal", Identity: "p@x"}}}
	var data []string
	for _, row := range c.identityKeyboard("42").InlineKeyboard {
		for _, b := range row {
			data = append(data, b.CallbackData)
		}
	}
	assert.Equal(t, []string{"approve_as:work:42", "approve_as:personal:42", "chg_back:42"}, data)
}
