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
