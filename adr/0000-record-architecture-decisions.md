# ADR 0000: Record architecture decisions

**Status:** Accepted (2026-06-25). Its immutability sentence is superseded by [ADR 0037](0037-amending-accepted-adrs.md), which allows dated, append-only amendments.

## Context
Darbaan is a security-sensitive project whose design was worked out in
discussion. We want the reasoning behind each significant decision to be
durable and reviewable, not lost in chat history.

## Decision
We use Architecture Decision Records. Each ADR is a numbered Markdown file in
`adr/` with Status, Context, Decision, Consequences. ADRs are immutable once
Accepted; a later ADR can supersede an earlier one.

## Consequences
Decisions are auditable and onboardable. Changing a decision is itself a
recorded, deliberate act.
