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

## Amendment (2026-06-25, review)
**How the risk result selects a chain.** A **router** consumes the pre-screener
verdict and picks the approval chain: low + no flags → the **light** chain;
medium/high or any flag → the **strict** chain, per a configured routing table.
The pre-screener runs as the mandatory first stage when compiled in. **If it is
not compiled in, the router defaults to the strict chain** (fail-safe) — absence
of a risk signal is treated as "could be risky," never as "low."

## Amendment (2026-06-27): no longer compile-time
The pre-screener is no longer selected via a build tag — ADR 0004's compile-time
mechanism was removed (#50), superseded by ADR 0017's runtime clients. It remains
"just another approver," now selected at **runtime** via the approval chains; the
"compile-time plugin" framing in the title and decision above is historical. The
fail-safe still holds: when no pre-screener is registered, the router defaults to
the strict chain.
