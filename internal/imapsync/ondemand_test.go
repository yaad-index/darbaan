package imapsync_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/imapsync"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// A registered inbox pulls on the first Trigger, then coalesces further triggers
// within the debounce window (silent-skip: ran=false, no error, no upstream dial),
// and pulls again once the window elapses (ADR 0028).
func TestOnDemandSyncDebounces(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\nbody one")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)

	od := imapsync.NewOnDemandSync()
	od.Register(inbound.DefaultInbox, syncer, 50*time.Millisecond)

	// First trigger pulls the one message.
	n, ran, err := od.Trigger(context.Background(), inbound.DefaultInbox)
	require.NoError(t, err)
	assert.True(t, ran, "first trigger runs a pull")
	assert.Equal(t, 1, n)

	// A second message lands upstream, but a trigger inside the window is coalesced:
	// silent-skip, no pull, so the new message is NOT pulled yet.
	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\nbody two")
	n, ran, err = od.Trigger(context.Background(), inbound.DefaultInbox)
	require.NoError(t, err)
	assert.False(t, ran, "trigger within the debounce window is skipped")
	assert.Equal(t, 0, n)
	msgs, err := store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Len(t, msgs, 1, "coalesced trigger did not pull the second message")

	// After the window elapses, a trigger pulls again and picks up the second.
	time.Sleep(60 * time.Millisecond)
	n, ran, err = od.Trigger(context.Background(), inbound.DefaultInbox)
	require.NoError(t, err)
	assert.True(t, ran, "trigger after the window runs a pull")
	assert.Equal(t, 1, n)
	msgs, err = store.List("agent", inbound.DefaultInbox)
	require.NoError(t, err)
	assert.Len(t, msgs, 2)
}

// An inbox that was never registered (not opted in, or bounce-only with no
// syncer) is a pure no-op: no pull, no error.
func TestOnDemandSyncNoOpForUnregisteredInbox(t *testing.T) {
	od := imapsync.NewOnDemandSync()
	n, ran, err := od.Trigger(context.Background(), "not-registered")
	require.NoError(t, err)
	assert.False(t, ran)
	assert.Zero(t, n)
}

// A zero/negative window means "no debounce": every trigger that is not already
// in flight pulls (there is no minimum gap).
func TestOnDemandSyncNoDebounceWindow(t *testing.T) {
	addr, user := startUpstream(t)
	appendMsg(t, user, "From: a@x.test\r\nSubject: one\r\n\r\nbody one")

	store := newInbound(t)
	syncer := imapsync.New(dialFor(addr), "INBOX", "agent", inbound.DefaultInbox, store, newState(t), 0)

	od := imapsync.NewOnDemandSync()
	od.Register(inbound.DefaultInbox, syncer, 0) // no debounce

	_, ran, err := od.Trigger(context.Background(), inbound.DefaultInbox)
	require.NoError(t, err)
	assert.True(t, ran)

	appendMsg(t, user, "From: b@x.test\r\nSubject: two\r\n\r\nbody two")
	n, ran, err := od.Trigger(context.Background(), inbound.DefaultInbox)
	require.NoError(t, err)
	assert.True(t, ran, "with no window every trigger pulls")
	assert.Equal(t, 1, n)
}
