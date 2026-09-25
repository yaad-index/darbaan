package telegram

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #119: the inline marker and the upload decision come from one predicate, so the
// card cannot promise a file that will never be sent.

// The boundary, tested on the predicate itself so every case is cheap. This is the
// single decision both the marker and the uploader read.
func TestFullBodyUploadableBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want bool
	}{
		{"empty", 0, false},
		{"one byte", 1, true},
		{"just under the cap", maxUpload - 1, true},
		{"exactly the cap", maxUpload, true},
		{"one over the cap", maxUpload + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fullBodyUploadable(tc.size))
		})
	}
}

// 🚨 The invariant the operator depends on: the marker names a file EXACTLY when one
// will be sent. Asserted as a biconditional over both branches rather than as two
// independent facts, because the defect was precisely that the two could disagree.
func TestMarkerNamesAFileExactlyWhenOneIsSent(t *testing.T) {
	longEnoughToTruncate := strings.Repeat("a", maxNotificationUnits*2)

	t.Run("under the cap: names the file and offloads", func(t *testing.T) {
		text, offloaded := formatNotification(notification{
			id: "1", from: "a@x.test", to: "b@y.test", subject: "s", size: 10,
			body: longEnoughToTruncate,
		})
		require.True(t, offloaded, "control: a truncated, uploadable body does offload")
		assert.Contains(t, text, fullBodyFilename, "and the marker names the file that will be sent")
		assert.Contains(t, text, "truncated")
		assert.Equal(t, offloaded, strings.Contains(text, fullBodyFilename),
			"names a file exactly when one is sent")
	})

	t.Run("over the cap: states the size and does NOT offload", func(t *testing.T) {
		oversize := strings.Repeat("a", maxUpload+1)
		text, offloaded := formatNotification(notification{
			id: "2", from: "a@x.test", to: "b@y.test", subject: "s", size: 10,
			body: oversize,
		})
		require.False(t, offloaded, "an over-cap body is not offloaded, so nothing is uploaded")
		assert.NotContains(t, text, fullBodyFilename,
			"and the marker must NOT name a file, because none will be sent")
		assert.Contains(t, text, "too large to attach")
		assert.Contains(t, text, humanSize(int64(len(oversize))), "the operator is told how big it is")
		assert.Equal(t, offloaded, strings.Contains(text, fullBodyFilename),
			"names a file exactly when one is sent")
	})
}

// The marker feeds the truncation budget, so a differently-sized marker must not
// push the card past the cap. Asserted on both branches, since they use different
// markers and only one of them existed before.
func TestTruncatedCardStaysWithinTheCapOnBothBranches(t *testing.T) {
	for name, body := range map[string]string{
		"uploadable": strings.Repeat("a", maxNotificationUnits*2),
		"over cap":   strings.Repeat("a", maxUpload+1),
	} {
		t.Run(name, func(t *testing.T) {
			text, _ := formatNotification(notification{
				id: "1", from: "a@x.test", to: "b@y.test", subject: "s", size: 10, body: body,
			})
			assert.LessOrEqual(t, utf16Len(text), maxNotificationUnits,
				"the rendered card must fit Telegram's cap whichever marker was chosen")
		})
	}
}
