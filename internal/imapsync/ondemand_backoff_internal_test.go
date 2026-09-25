package imapsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// backoffWindow is governed by one of three clauses — the doubling, the cap, or the
// floor — and which one fires depends on the operator's ratio of timeout to
// configured window, not on anything fixed. So each case below pins WHICH clause
// produced the value, using numbers where the three would disagree; a case where
// two of them coincide cannot tell you which one fired.
func TestBackoffWindowWhichClauseGoverns(t *testing.T) {
	const m = time.Minute

	for _, tc := range []struct {
		name        string
		minInterval time.Duration
		stall       time.Duration
		want        time.Duration
		governs     string
		// the values the OTHER clauses would have produced, asserted to differ so
		// the case is actually diagnostic
		others []time.Duration
	}{
		{
			name: "doubling governs", minInterval: 1 * m, stall: 2 * m,
			want: 4 * m, governs: "2x stall",
			others: []time.Duration{1 * m, 10 * m}, // floor, cap
		},
		{
			name: "cap governs", minInterval: 30 * time.Second, stall: 5 * m,
			want: 5 * m, governs: "10x minInterval",
			others: []time.Duration{10 * m, 30 * time.Second}, // doubling, floor
		},
		{
			name: "floor governs", minInterval: 5 * m, stall: 10 * time.Second,
			want: 5 * m, governs: "minInterval floor",
			others: []time.Duration{20 * time.Second, 50 * m}, // doubling, cap
		},
		{
			name: "no debounce configured: doubling, uncapped", minInterval: 0, stall: 3 * m,
			want: 6 * m, governs: "2x stall with no proportional cap to apply",
			others: []time.Duration{0}, // the floor/cap basis, which is absent
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := backoffWindow(tc.minInterval, tc.stall)
			assert.Equal(t, tc.want, got, "expected %s to govern", tc.governs)
			for _, other := range tc.others {
				assert.NotEqual(t, other, tc.want,
					"fixture is not diagnostic: another clause would also produce %s", other)
			}
		})
	}
}

// 🚨 The DEFAULT deployment is the one configuration where the doubling and the cap
// agree, so it is the one place a test proves nothing about which mechanism is in
// force. With the shipped defaults — a 1m window and a 5m bound on a pull — a
// deadline-ended pull stalls ~5m, so the doubling wants 10m and the cap
// (10x1m) is also 10m. They coincide exactly when timeout == 5 x minInterval.
//
// This is recorded as a test rather than a comment so that changing either default
// surfaces here, and so nobody later reads a passing default-config assertion as
// evidence that the doubling (or the cap) is what governs in production.
func TestBackoffWindowDefaultsAreTheDegenerateCase(t *testing.T) {
	const minInterval = time.Minute // DefaultSyncOnStatusInterval
	const stall = 5 * time.Minute   // ~OnDemandSyncTimeout, the bound on one pull
	doubling := stall * backoffStallFactor
	capped := minInterval * backoffCapFactor

	assert.Equal(t, doubling, capped,
		"at the shipped defaults the two clauses coincide; if this fails a default moved and the governing clause changed with it")
	assert.Equal(t, doubling, backoffWindow(minInterval, stall))
}

// The shared predicate keys on the context, not on the error: a context that ends
// mid-command surfaces as a transport error, never as context.DeadlineExceeded.
func TestEndedOnContext(t *testing.T) {
	live := context.Background()
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	transportErr := errors.New("imap: connection closed") // what a mid-command cancel really looks like

	assert.True(t, EndedOnContext(dead, transportErr),
		"a context that ended plus any error is a deferral, whatever the error says")
	assert.False(t, EndedOnContext(live, transportErr),
		"a real failure inside budget is NOT a deferral")
	assert.False(t, EndedOnContext(dead, nil),
		"a pull that completed cleanly is not a deferral even if the context has since ended")
	assert.False(t, EndedOnContext(live, nil))
}
