# ADR 0010: Multi-mailbox in v1; multi-agent deferred

**Status:** Accepted (2026-06-25)

## Context
Darbaan should front several mailboxes. Supporting several independent agent
principals is desirable but adds identity/permission machinery.

## Decision
**v1 is multi-mailbox + single-agent.** Darbaan fronts N upstream accounts, each
with its own credentials, filter rules, and approval policy. **Multi-agent**
(per-agent logins + an `agent x account x direction x gate` permission matrix)
is **deferred post-v1**, sketched so v1 does not foreclose it. The agent
pre-screener (ADR 0005) does not require multi-agent tenancy.

## Consequences
- v1 stays simple while leaving room for per-agent isolation later.

## Amendment (2026-06-25, review) — the deferred sketch
When multi-agent is added: each agent gets its own Darbaan credentials (ADR 0002)
identifying a principal; a **permission matrix** maps `(agent, account,
direction)` → allow/deny + which approval chain applies; per-agent credential
scoping ensures one agent's compromise cannot reach another's mailboxes; an
approver can itself be an agent principal. **None of this is built in v1.** It is
recorded so v1 schemas (agent identity on the audit log, per-account policy)
leave room for it without rework.
