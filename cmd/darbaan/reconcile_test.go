package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inboxcfg"
)

// reconcileTargets selects only enabled inboxes that have an upstream syncer,
// defaults the interval, and carries the cap config + audit log into the pass
// options (ADR 0026).
func TestReconcileTargets(t *testing.T) {
	synA := &imapsync.Syncer{}
	synD := &imapsync.Syncer{}
	syncers := map[string]*imapsync.Syncer{
		"on-with-syncer":      synA,
		"on-default-interval": synD,
		"off":                 {}, // disabled inbox: has a syncer but must be excluded
	}
	inboxes := []inboxcfg.Inbox{
		{Name: "on-with-syncer", ReconcileEnabled: true, ReconcileInterval: "2h", ReconcileCapFraction: 0.3, ReconcileCapFloor: 7},
		{Name: "on-no-syncer", ReconcileEnabled: true},        // enabled but no syncer → excluded
		{Name: "off", ReconcileEnabled: false},                // disabled → excluded
		{Name: "on-default-interval", ReconcileEnabled: true}, // enabled + syncer, no interval → default
	}

	targets := reconcileTargets(inboxes, syncers, nil)
	require.Len(t, targets, 2, "only enabled inboxes that have an upstream syncer")

	byName := map[string]reconcileTarget{}
	for _, tg := range targets {
		byName[tg.inbox] = tg
	}

	a, ok := byName["on-with-syncer"]
	require.True(t, ok)
	assert.Same(t, synA, a.syncer)
	assert.Equal(t, 2*time.Hour, a.interval)
	assert.Equal(t, 0.3, a.opts.CapFraction)
	assert.Equal(t, 7, a.opts.CapFloor)

	d, ok := byName["on-default-interval"]
	require.True(t, ok)
	assert.Equal(t, DefaultReconcileInterval, d.interval, "no interval ⇒ default")

	_, hasNoSyncer := byName["on-no-syncer"]
	assert.False(t, hasNoSyncer, "reconcile_enabled without an upstream syncer is excluded")
	_, hasOff := byName["off"]
	assert.False(t, hasOff, "a disabled inbox is excluded")
}
