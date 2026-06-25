# ADR 0002: Policy in a separate trusted box; credential isolation

**Status:** Accepted (2026-06-25)

## Context
The thing an email injection attacks is the agent's own judgment. Policy that
lives in the agent's prompt or behaviour can be argued away. The real mailbox
credentials, if held by the agent, can be exfiltrated.

## Decision
Policy lives in Darbaan, a separate component the agent does not control, and is
enforced **mechanically**. Darbaan holds the **real** mailbox credentials; each
agent only ever gets **Darbaan** credentials.

## Consequences
- Policy holds even if an agent is fully compromised.
- An injection that steals an agent's credentials gets a box that is already
  policy-limited, never the actual mailbox.
- Darbaan is a trust boundary; its own integrity is the thing to protect.

## Amendment (2026-06-25, review)
**Defining "Darbaan credentials" (how an agent authenticates).** Each agent
authenticates to Darbaan's IMAP and SMTP faces with **per-agent credentials** (a
username + secret/token) issued by Darbaan, over TLS. These identify the agent
principal and grant **only** Darbaan access, never upstream access. v1 is
single-agent (one credential set); the mechanism generalizes to many (ADR 0010).
