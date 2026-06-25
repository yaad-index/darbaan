# ADR 0005: Agent pre-screener as a compile-time plugin; risk routing

**Status:** Accepted (2026-06-25)

## Context
An automated agent can pre-screen queued mail for injection/exfiltration smell
before a human looks. But the core must not depend on an AI runtime.

## Decision
The agent pre-screener is **just another approver plugin**, selected via build
tag (ADR 0004). Darbaan's core carries **no AI dependency** and can be built
human-only. The pre-screener emits a **coarse** result: a level
(low/medium/high), reasons, and boolean flags (touches-secret, new-recipient,
external-domain, has-attachment). Routing: low with no flags takes the light
path (one human tap); medium/high or any flag takes the strict path.

## Consequences
- Coarse buckets avoid false precision; refine once real traffic is seen.
- Deployments choose their own AI dependency posture at build time.
