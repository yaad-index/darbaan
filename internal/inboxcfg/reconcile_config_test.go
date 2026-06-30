package inboxcfg_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

// The reconcile fields parse from the inboxes: doc, and default OFF when absent
// (opt-in, so an upgrade never starts retracting by surprise — ADR 0026).
func TestReconcileConfigParse(t *testing.T) {
	doc := []byte(`
inboxes:
  - name: work
    reconcile_enabled: true
    reconcile_interval: "2h"
  - name: personal
`)
	inboxes, err := inboxcfg.Parse(doc)
	require.NoError(t, err)
	require.Len(t, inboxes, 2)

	assert.True(t, inboxes[0].ReconcileEnabled)
	assert.Equal(t, "2h", inboxes[0].ReconcileInterval)

	assert.False(t, inboxes[1].ReconcileEnabled, "absent reconcile_enabled defaults OFF")
	assert.Empty(t, inboxes[1].ReconcileInterval)
}

func TestReconcileDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false}, // empty → runtime default
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"6h", 6 * time.Hour, false},
		{"nope", 0, true}, // unparseable
		{"0s", 0, true},   // zero rejected
		{"-1h", 0, true},  // negative rejected
	}
	for _, c := range cases {
		d, err := inboxcfg.Inbox{ReconcileInterval: c.in}.ReconcileDuration()
		if c.wantErr {
			assert.Error(t, err, "interval %q", c.in)
			continue
		}
		require.NoError(t, err, "interval %q", c.in)
		assert.Equal(t, c.want, d, "interval %q", c.in)
	}
}

// Validate fail-fasts on a bad interval only for an ENABLED inbox; a disabled
// inbox's interval is meaningless and not validated.
func TestValidateReconcileInterval(t *testing.T) {
	enabledBad := []inboxcfg.Inbox{{Name: "work", ReconcileEnabled: true, ReconcileInterval: "nope"}}
	assert.Error(t, inboxcfg.Validate(enabledBad), "enabled + bad interval is rejected at load")

	enabledZero := []inboxcfg.Inbox{{Name: "work", ReconcileEnabled: true, ReconcileInterval: "0s"}}
	assert.Error(t, inboxcfg.Validate(enabledZero), "enabled + zero interval is rejected")

	enabledOK := []inboxcfg.Inbox{{Name: "work", ReconcileEnabled: true, ReconcileInterval: "1h"}}
	assert.NoError(t, inboxcfg.Validate(enabledOK))

	enabledEmpty := []inboxcfg.Inbox{{Name: "work", ReconcileEnabled: true}}
	assert.NoError(t, inboxcfg.Validate(enabledEmpty), "enabled + empty interval uses the runtime default")

	disabledBad := []inboxcfg.Inbox{{Name: "work", ReconcileInterval: "nope"}}
	assert.NoError(t, inboxcfg.Validate(disabledBad), "a disabled inbox's interval is not validated")
}

func TestReconcileCapParse(t *testing.T) {
	doc := []byte("inboxes:\n  - name: work\n    reconcile_enabled: true\n    reconcile_cap_fraction: 0.3\n    reconcile_cap_floor: 10\n")
	inboxes, err := inboxcfg.Parse(doc)
	require.NoError(t, err)
	require.Len(t, inboxes, 1)
	assert.InDelta(t, 0.3, inboxes[0].ReconcileCapFraction, 1e-9)
	assert.Equal(t, 10, inboxes[0].ReconcileCapFloor)
}

// The cap fraction (0,1] and floor >=1 are validated only for an enabled inbox;
// zero means "runtime default".
func TestValidateReconcileCap(t *testing.T) {
	en := func(f float64, fl int) []inboxcfg.Inbox {
		return []inboxcfg.Inbox{{Name: "work", ReconcileEnabled: true, ReconcileCapFraction: f, ReconcileCapFloor: fl}}
	}
	assert.Error(t, inboxcfg.Validate(en(1.5, 0)), "fraction >1 rejected")
	assert.Error(t, inboxcfg.Validate(en(-0.1, 0)), "negative fraction rejected")
	assert.Error(t, inboxcfg.Validate(en(0, -1)), "floor <1 rejected")
	assert.NoError(t, inboxcfg.Validate(en(0.3, 1)))
	assert.NoError(t, inboxcfg.Validate(en(0, 0)), "zero fraction/floor = runtime default")

	disabled := []inboxcfg.Inbox{{Name: "work", ReconcileCapFraction: 9, ReconcileCapFloor: -5}}
	assert.NoError(t, inboxcfg.Validate(disabled), "the cap is not validated when reconciliation is disabled")
}
