package imapsync

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// OnDemandSync coalesces caller-triggered ("sync now") upstream pulls per inbox
// (ADR 0028). An IMAP STATUS for an enabled inbox calls Trigger; Trigger runs one
// incremental Syncer.Sync, but at most once per the inbox's debounce window and
// never concurrently with itself — so a burst of STATUS commands, or several
// agents sharing one inbox (ADR 0027), collapse to a single upstream dial.
//
// The debounce is per inbox and shared across every session (it lives here, not
// on a connection): N connected agents share one window rather than each getting
// their own and multiplying upstream load by N. Only inboxes an operator opted in
// (with an upstream syncer) are registered; Trigger is a cheap no-op for any
// other inbox.
type OnDemandSync struct {
	mu      sync.Mutex
	inboxes map[string]*onDemandInbox
}

// onDemandInbox is one registered inbox's syncer, debounce window, and the
// coalescing state guarded by OnDemandSync.mu.
type onDemandInbox struct {
	syncer      *Syncer
	minInterval time.Duration
	last        time.Time // completion time of the last on-demand pull
	inflight    bool      // a pull is running now (single-flight guard)
}

// NewOnDemandSync returns an empty coordinator; register inboxes with Register.
func NewOnDemandSync() *OnDemandSync {
	return &OnDemandSync{inboxes: map[string]*onDemandInbox{}}
}

// Register enables on-demand sync for an inbox with its syncer and debounce
// window. It is called once per opted-in inbox at wiring time (not concurrently),
// before any Trigger. A non-positive minInterval is treated as "no debounce"
// (every Trigger that is not already in flight pulls); callers pass a sane
// default instead.
func (o *OnDemandSync) Register(inbox string, syncer *Syncer, minInterval time.Duration) {
	o.inboxes[inbox] = &onDemandInbox{syncer: syncer, minInterval: minInterval}
}

// Trigger runs one incremental upstream pull for inbox if one is due — the
// debounce window since the last on-demand pull has elapsed and no pull is
// already in flight — and returns the count stored and whether a pull actually
// ran. It is a no-op (0, false, nil) for an unregistered inbox, or when the pull
// is debounced or coalesced away.
//
// The syncer dial is done WITHOUT holding the lock (it is a network round-trip),
// so concurrent Triggers for other inboxes proceed and a slow pull does not block
// the coordinator. The window is stamped from the pull's COMPLETION, so a slow
// pull does not immediately re-trigger.
func (o *OnDemandSync) Trigger(ctx context.Context, inbox string) (int, bool, error) {
	o.mu.Lock()
	in := o.inboxes[inbox]
	if in == nil {
		o.mu.Unlock()
		return 0, false, nil // not opted in / no upstream — nothing to pull
	}
	now := time.Now()
	if in.inflight || (!in.last.IsZero() && now.Sub(in.last) < in.minInterval) {
		o.mu.Unlock()
		return 0, false, nil // a pull is running, or the window has not elapsed
	}
	in.inflight = true
	o.mu.Unlock()

	n, err := in.syncer.Sync(ctx)

	o.mu.Lock()
	in.inflight = false
	in.last = time.Now() // start the window from completion, not from entry
	o.mu.Unlock()

	// Log the fire path (only when a pull actually ran, not the silent-skip) so an
	// on-demand pull is unambiguous in the logs — distinct from the background
	// poll's "inbound sync pulled messages" and from a skip that logged nothing. A
	// failed pull is left to the caller to log (the STATUS handler warns); here we
	// record the successful fire and its count.
	if err == nil {
		slog.Info("on-demand inbound sync ran", "inbox", inbox, "pulled", n)
	}
	return n, true, err
}
