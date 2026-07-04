# ADR 0028: On-demand inbound sync — pull the queried inbox on STATUS

**Status:** Proposed (2026-07-04)

## Context

Inbound sync is store-canonical and forward-only (ADR 0019): a per-inbox loop
polls the upstream mailbox on a fixed interval (`inbound-imap-poll-interval`,
default 60s) and pulls new mail into the store, which the IMAP read face
(ADR 0016) then serves. The interval is deliberately coarse — a steady
background poll, not a tight loop.

That coarseness is a latency floor the agent cannot cross. After the agent does
something that produces a reply — sends a message and expects an answer, has a
held submission approved, or runs a test round-trip — the new mail is not
visible on its IMAP face until the next scheduled poll lands it in the store.
The agent has no way to say "pull now"; it can only wait out the interval.

The natural IMAP verb for this is not `NOOP`. `NOOP` is a keep-alive clients
spam every few seconds while idle-polling, so tying an upstream pull to it —
even debounced — invites needless load and surprises. IMAP's explicit
"tell me about this mailbox" verb is `STATUS`: a low-frequency, deliberate
command a client issues to ask a named mailbox's message/unseen/uidnext counts,
typically for a mailbox it does not have selected. "Give me current status" is
an honest place to refresh first and then report.

`STATUS` is already implemented (`Status(mailbox, options)`): it resolves the
mailbox to an inbox the agent may read, re-lists that inbox from the store
**fresh on every call**, and reports the counts. It is a query — the selected
mailbox is untouched.

## Decision

Make `STATUS` the agent's **"sync now"**: when a client issues `STATUS` for an
inbox that has on-demand sync enabled, run an immediate, **debounced** on-demand
upstream pull of that inbox **before** computing the reply, so the returned
counts already include mail that arrived since the last background poll.

Because `Status` already re-lists the store fresh per call, the only change to
it is to trigger the pull up front; the existing `MESSAGES` / `UNSEEN` /
`UIDNEXT` computation then reports the grown set. `NOOP`/`CHECK` (`Poll`) stay a
true no-op — no keep-alive triggers an upstream dial.

### Trigger

`Status` runs on the connection's own goroutine (go-imap serializes commands per
connection), so a bounded upstream pull inline is safe. For the resolved inbox
it calls a debounced trigger that runs one incremental `Syncer.Sync` (the same
forward pull the background loop runs), then the fresh re-list reports the
result. It needs no SELECT — `STATUS` names its own mailbox — so an agent can
refresh a mailbox it is not currently reading.

The trigger is a clean no-op when:

- the queried inbox has no upstream syncer (a bounce-only / sync-disabled inbox
  — nothing to pull);
- on-demand sync is not enabled for the inbox; or
- the inbox's debounce window has not elapsed.

A sync error never fails the `STATUS`: the pull is best-effort, the error is
logged, and `STATUS` reports the store's current counts anyway. A failed
on-demand pull is no worse than waiting for the next background poll.

### Debounce (mandatory per-inbox rate-limit)

`STATUS` is far less frequent than `NOOP`, but a client (or several agents
sharing one inbox in a multi-agent deployment, ADR 0027) can still issue it in
bursts. So on-demand sync is **coalesced per inbox**: after an on-demand pull
completes, further triggers for that inbox are suppressed until a configurable
window elapses. Within the window a `STATUS` does **no** upstream work — it still
reports whatever is already in the store (so a background poll's mail is
surfaced), but it does not dial.

The debounce is **per inbox and shared across sessions**, not per connection —
otherwise N connected agents would each get their own window and multiply the
upstream load by N. It also refuses to start a second pull for an inbox while
one is already in flight (a single-flight guard), so a burst collapses to one
dial. The window is measured from pull **completion**, so a slow pull does not
immediately re-trigger.

A **failed** pull starts the window too — the completion timestamp is stamped
whether the pull succeeded or errored. This is deliberate anti-storm behavior: a
persistently unreachable or erroring upstream cannot be turned into a dial-storm
by repeated `STATUS`, since each failed attempt still opens a fresh debounce
window. The background poll loop (ADR 0019) is the fallback that keeps retrying
and eventually recovers, so suppressing on-demand retries within the window
loses nothing.

### Counts, not unsolicited updates (v1 boundary)

`STATUS` reports fresh counts computed after the pull; it pushes **no**
unsolicited `EXISTS`/`EXPUNGE` into a concurrently-selected session (`STATUS`
carries no update channel — it returns a status reply). An agent that sees a
higher `MESSAGES`/`UIDNEXT` count then `SELECT`s (or re-examines) the inbox to
fetch the new mail — the honest, standard flow.

This keeps the change append-safe by construction: new synced mail carries
strictly higher store ids than everything present, so it appends at the tail; a
**shrink or reorder** — a reconcile retraction (ADR 0026) removing a message, or
a filter now hiding one — simply surfaces as a changed count and is picked up on
the client's next `SELECT`, never as a mid-session sequence-number desync. v1
sends no unsolicited `EXPUNGE`; convergent in-session update signalling is a
possible follow-up, out of scope here.

### Config

On-demand sync is **opt-in per inbox**, matching the `reconcile_enabled` idiom
(ADR 0026) and reflecting that it changes what `STATUS` costs (a bounded upstream
round-trip) — an operator turns it on deliberately, not by upgrade surprise. Two
per-inbox fields under the `inboxes:` schema (ADR 0023):

- `sync_on_status` (bool, default false) — enable the on-demand pull on `STATUS`
  for this inbox.
- `sync_on_status_interval` (duration, empty → runtime default) — the debounce
  window: the minimum gap between on-demand upstream pulls of this inbox. The
  runtime default is 60s. Only meaningful when `sync_on_status` is set.

An inbox with no upstream syncer ignores the setting (nothing to pull). The
background poll loop (ADR 0019) is unchanged and runs regardless; on-demand sync
only lets the agent skip the wait between its cycles.

## Boundaries

- **No new IMAP verb.** This reuses `STATUS` — a standard client "tell me about
  this mailbox" query — rather than inventing an extension. Any IMAP client gets
  it for free; no client change is needed.
- **`NOOP`/`CHECK` are unchanged** — a true no-op. No keep-alive triggers an
  upstream dial, so idle-polling clients impose no on-demand load.
- **Read-only upstream is unchanged** (ADR 0002): the on-demand pull is the same
  read-only forward `Sync` the background loop runs.
- **No push / IDLE.** This is pull-on-STATUS, not server-initiated push. `IDLE`
  stays a park (it blocks until the client stops); a client wanting timely mail
  issues `STATUS`.
- **Counts only**, no unsolicited `EXISTS`/`EXPUNGE` (above).

## Consequences

- An agent that wants its reply now issues a `STATUS` and the returned counts
  already reflect it, bounded only by the upstream fetch — no longer by the poll
  interval. It then `SELECT`s to read.
- Upstream load is bounded by the per-inbox debounce window regardless of how
  often clients `STATUS` or how many share an inbox, so the "sync now" path
  cannot be turned into an amplification vector.
- `NOOP` stays cheap and dial-free, so idle keep-alives cost nothing upstream.
- The change is inert until an operator opts an inbox in, so existing
  deployments are unaffected.
