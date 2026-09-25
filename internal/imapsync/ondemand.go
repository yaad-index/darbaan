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
	minInterval time.Duration // the operator's configured window; the floor and the backoff's basis
	window      time.Duration // the window actually in force: minInterval until a deadline-ended pull widens it
	last        time.Time     // completion time of the last on-demand pull
	inflight    bool          // a pull is running now (single-flight guard)
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
	o.inboxes[inbox] = &onDemandInbox{syncer: syncer, minInterval: minInterval, window: minInterval}
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
	if in.inflight || (!in.last.IsZero() && now.Sub(in.last) < in.window) {
		o.mu.Unlock()
		return 0, false, nil // a pull is running, or the window has not elapsed
	}
	in.inflight = true
	o.mu.Unlock()

	start := time.Now()
	n, err := in.syncer.Sync(ctx)
	stall := time.Since(start)

	o.mu.Lock()
	in.inflight = false
	in.last = time.Now() // start the window from completion, not from entry
	// Back off when the pull ended on its caller's context rather than finishing
	// (#258). Without this the next STATUS, one normal window later, hands a fresh
	// agent session another full-length stall: the configured window (a minute by
	// default) is shorter than the bound on a pull (five minutes), so a
	// silent-but-connected upstream keeps some session stalled for most of the
	// elapsed time. A clean pull resets the window, so a recovered upstream is
	// prompt again on its first success.
	if EndedOnContext(ctx, err) {
		in.window = backoffWindow(in.minInterval, stall)
	} else {
		in.window = in.minInterval
	}
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

// EndedOnContext reports whether a pull stopped because the caller's context
// ended rather than because the upstream genuinely failed.
//
// It keys on ctx.Err() and NOT on the returned error, and that is the whole
// subtlety: a context that expires while an IMAP command is in flight surfaces as
// the client's closed-connection error, never as context.DeadlineExceeded, so
// classifying on the error would miss exactly the case that matters. It lives here,
// in one place, because two callers need the same answer for different reasons —
// Trigger sizes the next window from it, and the wiring site decides whether to
// swallow the outcome as a deferral — and a predicate this easy to get wrong should
// not be written twice.
//
// A shutdown cancellation also satisfies it. That is harmless for both uses: the
// window is about to stop mattering, and a cancelled pull is genuinely not an
// upstream fault.
func EndedOnContext(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil
}

// Backoff sizing for a pull that ended on its context. Both factors are
// deliberate choices, recorded because a number with no stated basis reads later
// as though it were measured:
//
//   - The window is twice the stall actually observed, not a multiple of the
//     configured window. The stall is the thing that hurt, and sizing from it needs
//     no knowledge of the caller's bound — which lives at the wiring site, not
//     here. Two-to-one turns "stalled for most of the elapsed time" into "stalled
//     for about a third of it".
//   - The cap is ten times the operator's configured window, so an operator who
//     chose a coarse window gets a proportionally coarse ceiling rather than one
//     picked here. It bounds how stale on-demand can get for an upstream that has
//     recovered; the background poll keeps syncing throughout, so the cost of a
//     too-wide window is a convenience delay, never missed mail.
const (
	backoffStallFactor = 2
	backoffCapFactor   = 10
)

// backoffWindow sizes the next-eligible window after a pull ended on its context.
func backoffWindow(minInterval, stall time.Duration) time.Duration {
	w := stall * backoffStallFactor
	if w < minInterval {
		w = minInterval
	}
	// A non-positive minInterval means the operator asked for no debounce, so there
	// is no configured window to take a proportional ceiling from. The backoff is
	// still applied — with no debounce a broken upstream would otherwise re-stall
	// immediately, which is the worst version of this bug — and it is bounded
	// anyway, because the stall it is derived from is bounded by the caller.
	if minInterval > 0 {
		if capped := minInterval * backoffCapFactor; w > capped {
			w = capped
		}
	}
	return w
}
