package imapsync_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// #258: after a pull that ended on its context, the next trigger is suppressed so a
// fresh agent session does not inherit another full-length stall.
//
// The debounce window is registered as ZERO here on purpose. With no debounce a
// trigger is never suppressed by the normal window, so a suppressed second trigger
// can only be the backoff — there is no other mechanism in play, and the assertion
// needs no sleeps to be deterministic.
func TestOnDemandBackoffSuppressesNextTriggerAfterContextEndedPull(t *testing.T) {
	addr, reached, release := startHangingUpstream(t, "SELECT")
	defer close(release)

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	od := imapsync.NewOnDemandSync()
	od.Register("work", syncer, 0) // no debounce: only a backoff can suppress

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-reached; cancel() }()

	ran := make(chan bool, 1)
	go func() {
		_, r, err := od.Trigger(ctx, "work")
		require.Error(t, err, "the pull ended on its context")
		ran <- r
	}()
	select {
	case r := <-ran:
		require.True(t, r, "control: the first trigger did run a pull")
	case <-time.After(5 * time.Second):
		t.Fatal("the first trigger never returned")
	}

	// Immediately, with a healthy context: this would have run before #258, because
	// the registered window is zero.
	_, r, err := od.Trigger(context.Background(), "work")
	assert.NoError(t, err)
	assert.False(t, r, "the next trigger is inside the backoff window, so no second stall is started")
}

// The control for the test above, and the half that proves zero-debounce does not
// suppress by itself: against a healthy upstream two consecutive triggers both run.
func TestOnDemandZeroDebounceDoesNotSuppressCleanPulls(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\nbody one")

	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	od := imapsync.NewOnDemandSync()
	od.Register("work", syncer, 0)

	_, r1, err := od.Trigger(context.Background(), "work")
	require.NoError(t, err)
	assert.True(t, r1, "first clean pull ran")

	_, r2, err := od.Trigger(context.Background(), "work")
	require.NoError(t, err)
	assert.True(t, r2, "a clean pull leaves the window at the configured zero, so the next trigger runs")
}

// A clean pull RESETS a window that a previous deadline-ended pull had widened, so a
// recovered upstream becomes prompt again rather than staying backed off. The dial
// switches from the hanging listener to a healthy one, which is what lets one
// coordinator see a failure and then a recovery.
func TestOnDemandBackoffResetsAfterARecoveredPull(t *testing.T) {
	hangAddr, reached, release := startHangingUpstream(t, "SELECT")
	defer close(release)
	workAddr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\nbody one")

	var dials atomic.Int32
	dial := func() (*imapclient.Client, error) {
		if dials.Add(1) == 1 {
			return dialFor(hangAddr)()
		}
		return dialFor(workAddr)()
	}

	syncer := imapsync.New(imapsync.DialFunc(dial), "INBOX", "agent", inbound.DefaultInbox, newInbound(t), newState(t), 0)
	od := imapsync.NewOnDemandSync()
	od.Register("work", syncer, 0)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-reached; cancel() }()
	done := make(chan struct{})
	go func() { _, _, _ = od.Trigger(ctx, "work"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the hung pull never returned")
	}

	// The backoff is twice the observed stall, and the stall here is the few
	// milliseconds to reach SELECT and cancel, so this wait clears it by a wide
	// margin without depending on the exact figure.
	time.Sleep(2 * time.Second)

	_, ran, err := od.Trigger(context.Background(), "work")
	require.NoError(t, err, "the upstream has recovered")
	require.True(t, ran, "control: the backoff window had elapsed, so this pull ran")

	_, again, err := od.Trigger(context.Background(), "work")
	assert.NoError(t, err)
	assert.True(t, again, "the clean pull reset the window to the configured zero; it is not still backed off")
}
