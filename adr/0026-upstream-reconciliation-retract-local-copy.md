# ADR 0026: Upstream reconciliation — retract the local copy when a message leaves the source

**Status:** Proposed (2026-06-30)

## Context

Inbound sync is **store-canonical** and **forward-only** (ADR 0019): each cycle
tracks the mailbox `UIDVALIDITY` and the highest synced UID and pulls only
higher UIDs. ADR 0019 explicitly deferred "upstream deletion/flag
reconciliation" as a follow-up — this ADR is that follow-up, scoped to
**presence reconciliation** (not flag sync).

The gap today: once a message is synced, its local copy persists **forever**.
There is no retraction path —

- the agent read face is read-only (`Delete` / `Expunge` return read-only), and
- there is no admin retract.

So if a message is **removed from the source mailbox** — deleted, archived out,
or (for a label-folder-scoped inbox, ADR 0023) un-labeled so it leaves the
synced folder — Darbaan keeps serving its local copy indefinitely. For a
label-folder-scoped inbox this is acute: an **accidental tag is unrecoverable**,
and the operator cannot pull a mistakenly-shared message back out. More
generally, stale mail lingers in the agent's view after it is gone upstream.

Operator requirement (2026-06-30): when a message leaves the source mailbox,
Darbaan **drops its local copy**. Crucially, the upstream is **never modified** —
Darbaan does not delete from the real mailbox (read-only upstream is a hard
invariant, ADR 0002). Retraction is purely about Darbaan's own synced copy.

## Decision

Add a periodic, **per-inbox reconciliation pass** alongside the forward sync.

1. **List** the current set of upstream UIDs for the inbox's mailbox.
2. For any **synced** message whose upstream UID is no longer present, **hard-
   remove the local copy** — the metadata record and its content blob
   (ADR 0018) — so it disappears from the read face entirely.

Hard remove, not hide (the operator's call, 2026-06-30): the copy is gone, not
merely filtered out. Each retraction is written to the **audit log** (ADR 0007
chain) so it is traceable.

### Invariants and guards

- **Read-only upstream (ADR 0002).** Reconciliation only *reads* the upstream
  UID listing; it removes local copies only. The real mailbox is never touched.
- **Synced messages only.** Darbaan-**generated** inbound (the signed bounces in
  the inbound store, ADR 0007/0016) has no upstream UID and is **never** subject
  to reconciliation. The pass keys strictly off the upstream-UID present on
  synced records.
- **`UIDVALIDITY` change → do not reconcile-delete.** A `UIDVALIDITY` bump means
  the whole UID space changed (mailbox reset); that is a full re-sync per
  ADR 0019, not a signal that every message was deleted. Skip presence-deletion
  that cycle.
- **Failed / incomplete listing → skip the cycle.** Reconciliation deletes only
  on a *successful, complete* UID listing. A transient IMAP error (or a partial
  listing) is a no-op for that cycle — **never delete on uncertainty**
  (fail-safe).
- **Safety cap.** If a single pass would purge more than a configurable fraction
  of the inbox's synced set, **hold and log/alert** instead of auto-purging — a
  backstop against a source-side anomaly (e.g. a mass un-label) silently
  emptying the store.

### Cadence and configuration

- A **configurable reconcile interval**, independent of (and typically longer
  than) the forward poll — a full UID listing is heavier than incremental sync.
- **Per-inbox enable.** Reconciliation is configured per inbox (ADR 0023); a
  label-folder-scoped inbox is the primary case (un-labeling = retraction).

### Re-appearance

If a message returns to the source after retraction (e.g. re-applying a label
adds it back to the folder with a **new** folder UID above the high-water),
forward sync re-pulls it naturally (ADR 0019). No special handling: retract on
exit, re-sync on return.

## Boundaries / non-goals (this increment)

- **Presence only, not flag sync.** This reconciles *gone-from-source →
  gone-locally*. Bidirectional flag/keyword reconciliation is separate
  (ADR 0020 already covers agent→upstream label write-through).
- **Upstream is never modified** — no upstream delete/expunge, ever.
- **Not real-time.** Retraction is bounded by the reconcile interval; IMAP
  IDLE / `CONDSTORE` / `QRESYNC` for faster, cheaper detection is a follow-up.
- A held / decided inbound message (ADR 0021) that leaves the source is
  retracted like any other; its persisted decision goes with the record.

## Consequences

- Un-tagging, deleting, or archiving-out a message **retracts** Darbaan's local
  copy — accidental shares are recoverable, and stale mail no longer lingers in
  the agent's view.
- The upstream stays untouched: the operator's real mailbox is never at risk
  from reconciliation.
- Cost: a periodic full UID listing per reconciled inbox (metadata-only, bounded;
  heavier than incremental sync, hence the separate, longer interval).
- The guards trade a slightly slower retraction (skip-on-error, hold-on-cap) for
  the guarantee that a transient fault or a `UIDVALIDITY` reset can never
  mass-delete the store.

## Follow-ups

- IMAP IDLE / `CONDSTORE` / `QRESYNC` for push / cheaper incremental
  reconciliation instead of full UID listing.
- Full bidirectional flag/keyword reconciliation (beyond presence).

Relates to ADR 0001, 0002, 0007, 0016, 0018, 0019, 0020, 0021, 0023.
