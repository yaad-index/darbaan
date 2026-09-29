# ADR 0039: A crash-safe re-send claim and an "outcome unknown" state

**Status:** Proposed

## Context

An approved outbound message whose send failed can be sent again with `ReSend`. `ReSend` reads the
record, checks that it is re-sendable, and sends. Two re-sends of the same message issued close
together can both pass the check and both deliver (#308). Re-send is a manual operator action, so
the race needs a near-simultaneous double-fire, but the result is a duplicate message to a real
recipient, which the gate exists to prevent.

Two further cases leave the operator unable to tell whether a message went out:

1. **A process that stops mid-send** (crash, restart, redeploy) leaves no trace of the attempt. The
   next re-send happens blind.
2. **A send cut off after the body was transmitted but before the server's final reply** (the
   connection drops or the overall send deadline, #362, fires at that point). The server may have
   accepted and delivered the message, but it is classed as a transient failure and is
   re-sendable without any warning.

Three facts from the current code make a simple design sufficient:

- **One process owns the store.** The bbolt file is opened for writing with an exclusive lock, and
  `ReSend` is reachable only through `serve`'s admin API. A check-and-set inside one bbolt `Update` is
  therefore atomic against every concurrent re-send; no cross-process lock is needed.
- **The first send cannot race a re-send**: `ReSend` requires a recorded `SendErr`, which exists only
  after an attempt.
- **Outbound sends now have an overall deadline and honour cancellation** (#362, fixed in #363), so
  anything held for the duration of a send is bounded.

## Decision

### 1. Claim before a re-send, atomically

- The stored record gains an in-flight marker: the time a re-send started and the actor. It is
  additive and zero by default; existing records read as not in flight and nothing is migrated.
- `ReSend` claims the record in one transaction, requiring: status approved, a recorded `SendErr`, and
  no claim present. It then sets the claim and commits.
- A second concurrent `ReSend` fails the claim with a distinct error, surfaced as a conflict ("a
  re-send of this message is already in progress"), not as "not re-sendable".
- `SendErr` is **not** cleared by the claim, so the message stays visibly failed while the attempt
  runs.
- Checks that read only configuration (for example that the approved-as inbox still resolves) run
  **before** the claim, so no early return can leave a claim behind.

### 2. Release the claim in the transaction that records the outcome

Recording the attempt (sent, or approved with a fresh `SendErr`) clears the claim in the same
transaction. There is no moment where the claim is gone but the result is not recorded.

### 3. A new operator-visible state: "outcome unknown"

"Outcome unknown" is a `SendErr` with a fixed, recognisable text plus an audit event. The message
stays re-sendable, and the operator decides, knowing a copy may already have gone out. It is reached
two ways:

- **At store open:** any record still carrying a claim belongs to a process that died, because only
  one process can hold the store. In one transaction per record: clear the claim, set the
  outcome-unknown `SendErr` (reason: re-send interrupted), and write a `resend_interrupted` audit
  event.
- **During a send:** the sender runs the SMTP transaction step by step (mail, recipients, data,
  write the body, close the data stream) instead of one combined call, so it can tell where a
  failure happened:
  - a failure **before** the body is closed is an ordinary transient failure, as before this ADR;
  - the server **answering** at close decides it: a permanent (5xx) rejection stays permanent, a
    temporary (4xx) rejection is an ordinary transient failure (it answered and did not accept);
  - **no answer** at close (connection dropped, deadline, cancellation) returns a distinct
    outcome-unknown error, recorded as the outcome-unknown `SendErr` (reason: no final reply) with an
    audit event.
  - **once close returns success, the attempt is sent**, whatever happens afterwards: a failure on
    `QUIT` or on closing the connection must never turn a delivered message into a failure, because
    that is exactly the duplicate this ADR prevents.
  - This send-side path applies to **every** send, including the first send after approve, not only
    re-sends.
- **Outcome unknown never triggers the delivery-failure bounce** sent to the agent: the message may
  have been delivered, so reporting it as failed would be false.

The queue listing and the Telegram card show "outcome unknown" distinctly from an ordinary failure,
and **re-sending an outcome-unknown message requires an explicit acknowledgement**: a field on the
re-send request that the admin API rejects without, a two-step button on the card, and a flag on the
CLI. Showing the warning is not enough, because the API and CLI can re-send by id without looking.

### 4. What this does not solve

A process that stops after the upstream server accepted the message but before the result was
recorded, with no claim involved (a first send, not a re-send), leaves a delivery the record cannot
see. No local marker makes delivery exactly-once. This ADR's aim is narrower: never lose track of an
interrupted re-send, and never present a possibly-delivered message as a plain failure.

## Consequences

- One additive field on the stored record, one startup reconciliation, one new error, one new audit
  event, and a distinguishable failure state in the admin API, the queue listing and the bot.
- The SMTP backend stops using the library's combined send call. Its tests gain a server that stalls
  at each step, including after the body.
- Tests the implementation must include: two concurrent re-sends against a blocking sender, asserting
  exactly one delivery and one in-progress conflict; a record reopened with a leftover claim,
  asserting the outcome-unknown state and the audit event; a send cut off after the body, asserting
  outcome-unknown rather than transient; a permanent rejection at close staying permanent; a temporary rejection at close staying transient;
  a success at close followed by a dropped connection recording the message as sent; an
  outcome-unknown message producing no bounce; a re-send of an outcome-unknown message refused without
  the acknowledgement.
