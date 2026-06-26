# ADR 0019: Inbound mailbox sync — store-canonical incremental pull, lazy content, no filter (v1)

**Status:** Proposed (2026-06-26)

## Context

The MVP IMAP read face serves only Darbaan-generated bounces from the store
(ADR 0016). The inbound store is now tiered (ADR 0018). The next step is the
real inbound half of the original design: Darbaan pulls the agent's actual
mailbox so the agent reads real mail *through Darbaan*, never the provider
directly (ADR 0001, 0002).

ADR 0001/0016 already settled the shape: **store-canonical, not a live proxy** —
hiding messages from a live upstream is a UID/sequence-number hazard. So inbound
is a *sync into the store*, served over the read face.

This ADR scopes the **first increment: sync only, no filter.** The inbound
filter (hide / allow / hold-for-human, ADR 0008) is deferred to its own later
increment. The maintainer's explicit premise (2026-06-26): with no filter, the
agent has **full read access to the entire synced mailbox**. That is accepted
for the sync mechanism; the filter is the access-control layer that comes after.

## Decision

**Darbaan syncs the upstream mailbox into its inbound store and serves it over
the existing IMAP read face.** No live proxying.

- **Credential isolation (ADR 0002).** Darbaan connects to the upstream IMAP
  with the real provider credentials it holds; the agent only ever gets Darbaan
  credentials. The sync is **read-only on the upstream** in v1 (it pulls; it
  does not write flags/deletes back — that is a later refinement).
- **Incremental pull.** Track the upstream mailbox's `UIDVALIDITY` and the
  highest synced UID; each cycle fetches only messages with a higher UID. A
  `UIDVALIDITY` change (mailbox reset) triggers a re-sync. Upstream
  deletion/flag reconciliation is a later refinement; v1 is append-mostly.
- **Lazy content fetch.** Sync message **headers/metadata eagerly** (small, into
  bbolt); fetch **bodies + attachments on demand**, storing them as blobs
  (ADR 0018). The IMAP read face fetches content **per-FETCH** rather than
  reassembling the whole mailbox at SELECT — this is the read-time half ADR 0018
  named as future. Combined with tiering, a GB-scale mailbox stays viable:
  metadata in bbolt, content on the filesystem, loaded only when actually read.
- **No filter (this increment).** Everything synced is exposed to the agent.
  The full mailbox is readable by the agent until the filter lands.
- **Trigger.** Periodic poll on a configured interval for v1; IMAP IDLE (push)
  is a later optimization (mirrors the outbound's poll-first simplicity).
- **Store-canonical.** Synced messages live in Darbaan's own UID namespace in
  the inbound store; the agent's view is the store, decoupled from upstream
  availability per read.

## Boundaries / non-goals (this increment)

- **No filter** — hide/allow/hold-for-human is deferred (ADR 0008, next
  increment). Until it lands, point the sync at a non-sensitive / test mailbox.
- **No write-back** to the upstream (read-only pull; the agent's flag/delete
  changes in Darbaan do not propagate upstream yet).
- **Single mailbox** — multi-agent/multi-mailbox stays deferred (ADR 0010).
- **No pre-screener** on inbound (#29, later).

## Consequences

- The agent reads real mail through Darbaan — the inbound half of the vision,
  minus the access control.
- Lazy fetch + tiering make a large mailbox practical; SELECT no longer
  reassembles everything.
- Full mailbox access for the agent until the filter increment — the deliberate,
  named trade for getting the sync mechanism working first.
- Per-mailbox sync state (`UIDVALIDITY` + last UID) is persisted.

## Follow-ups

- **Inbound filter** (ADR 0008): hide / allow / hold-for-human — the
  access-control layer; hold-for-human reuses the admin-API + Telegram approval
  surface, mirroring the outbound sluice.
- Upstream deletion/flag reconciliation (bidirectional sync).
- IMAP IDLE (push) instead of polling.
- Inbound pre-screener (#29).

Relates to ADR 0001, 0002, 0008, 0010, 0016, 0018.
