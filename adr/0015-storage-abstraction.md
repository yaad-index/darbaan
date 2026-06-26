# ADR 0015: Abstract storage behind interfaces; config-selected backend

**Status:** Accepted (2026-06-26)

## Context
v1 uses bbolt for both the message store and the audit log. The storage engine
should be swappable for another later (SQLite, Postgres, a remote KV, ...) by a
**simple config change**, without rewiring call sites. Requirement from the
maintainer, 2026-06-26: make it possible for the future, do not build the
alternatives now.

## Decision
Persistence sits behind interfaces:
- **`MessageStore`** — the sluice: enqueue / list / get / set-status.
- **`AuditLog`** — append / verify (ADR 0011).

Each is chosen by a **config-selected factory** (`store.type`, `audit.type`),
the same registry pattern as approvers (ADR 0004) and backends (ADR 0009). v1
implements **bbolt only** for `MessageStore`, and **null + bbolt** for
`AuditLog` (ADR 0011). No other backends are built now — only the seam. Call
sites depend on the interfaces, never on bbolt directly.

## Consequences
- A future store is an implementation plus a config value, no call-site changes.
- Only the seam ships in v1; alternative backends are explicitly out of scope
  until a real need arises.
- Message store and audit log are **separate stores** (ADR 0011 amendment), so a
  deployment can disable audit (`audit.type: null`) independently.
