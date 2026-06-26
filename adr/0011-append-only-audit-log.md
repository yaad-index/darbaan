# ADR 0011: Append-only audit log

**Status:** Accepted (2026-06-25)

## Context
For trust, it must always be visible what was sent and who or what authorized it.

## Decision
Darbaan keeps an **append-only** audit log keyed by **agent identity**: every
queued draft, every verdict, who/what approved or rejected, every retry, and
both the original and any human-edited version of a draft (ADR 0004).

## Consequences
- Full provenance for every send and rejection.
- The log is a record to protect and, for permanent rejections, to surface (ADR 0006).

## Amendment (2026-06-25, review)
**Integrity:** the log is **hash-chained** — each entry carries the hash of the
previous, so tampering or truncation is evident. This is in v1 (cheap, high
value). **Retention:** configurable; v1 default is keep-all. Rotation/retention
is an operator setting; any rotation must preserve the chain across segments.

## Amendment (2026-06-26, review) — pluggable + optional audit
Auditing is a **pluggable component** (registry + config, the same pattern as
approvers and backends), selected by `audit.type`. v1 ships two implementations:
- **null** — no-op; audit disabled (for a simple single-agent, single-approval
  deployment where the chain is more than the user needs).
- **bbolt** — the hash-chained, tamper-evident log, in **its own store**,
  separate from the message store.

Putting the audit log in its own store (no longer inside the message store's
write transaction) **drops the prior atomic enqueue+audit guarantee**: audit
becomes **best-effort**, written after the operation, with the message store as
the source of truth. This is a deliberate trade for the off-switch and
modularity. The hash chain stays tamper-evident (blockchain-like, not a
blockchain — no consensus); pluggability leaves room for a stronger external
append-only sink later without touching call sites.
