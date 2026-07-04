package inboxcfg_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

// The sync_on_status fields parse from the inboxes: doc, and default OFF when
// absent (opt-in, so an upgrade never changes what STATUS costs by surprise —
// ADR 0028).
func TestSyncOnStatusConfigParse(t *testing.T) {
	doc := []byte(`
inboxes:
  - name: work
    sync_on_status: true
    sync_on_status_interval: "30s"
  - name: personal
`)
	inboxes, err := inboxcfg.Parse(doc)
	require.NoError(t, err)
	require.Len(t, inboxes, 2)

	assert.True(t, inboxes[0].SyncOnStatus)
	assert.Equal(t, "30s", inboxes[0].SyncOnStatusInterval)

	assert.False(t, inboxes[1].SyncOnStatus, "absent sync_on_status defaults OFF")
	assert.Empty(t, inboxes[1].SyncOnStatusInterval)
}

func TestSyncOnStatusDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false}, // empty → runtime default (60s)
		{"15s", 15 * time.Second, false},
		{"1m", time.Minute, false},
		{"nope", 0, true}, // unparseable
		{"0s", 0, true},   // zero rejected
		{"-5s", 0, true},  // negative rejected
	}
	for _, c := range cases {
		d, err := inboxcfg.Inbox{SyncOnStatusInterval: c.in}.SyncOnStatusDuration()
		if c.wantErr {
			assert.Error(t, err, "interval %q", c.in)
			continue
		}
		require.NoError(t, err, "interval %q", c.in)
		assert.Equal(t, c.want, d, "interval %q", c.in)
	}
}

// Validate fail-fasts on a bad debounce window only for an ENABLED inbox; a
// disabled inbox's interval is meaningless and not validated.
func TestValidateSyncOnStatusInterval(t *testing.T) {
	enabledBad := []inboxcfg.Inbox{{Name: "work", SyncOnStatus: true, SyncOnStatusInterval: "nope"}}
	assert.Error(t, inboxcfg.Validate(enabledBad), "enabled + bad interval is rejected at load")

	enabledZero := []inboxcfg.Inbox{{Name: "work", SyncOnStatus: true, SyncOnStatusInterval: "0s"}}
	assert.Error(t, inboxcfg.Validate(enabledZero), "enabled + zero interval is rejected")

	enabledOK := []inboxcfg.Inbox{{Name: "work", SyncOnStatus: true, SyncOnStatusInterval: "15s"}}
	assert.NoError(t, inboxcfg.Validate(enabledOK))

	enabledEmpty := []inboxcfg.Inbox{{Name: "work", SyncOnStatus: true}}
	assert.NoError(t, inboxcfg.Validate(enabledEmpty), "enabled + empty interval uses the runtime default")

	disabledBad := []inboxcfg.Inbox{{Name: "work", SyncOnStatusInterval: "nope"}}
	assert.NoError(t, inboxcfg.Validate(disabledBad), "a disabled inbox's interval is not validated")
}
