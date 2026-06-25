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
