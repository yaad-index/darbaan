# ADR 0003: The outbound sluice trap, fail-closed and default-deny

**Status:** Accepted (2026-06-25)

## Context
Sending is the dangerous half: exfiltration and unauthorized action happen on
the send path. Reading is recoverable; sending is not.

## Decision
Every outbound message is trapped in **the sluice** (the outbound hold/queue).
Darbaan accepts the SMTP submission (250 OK) and enqueues it; nothing auto-sends.
The default disposition is **block (default-deny)**: out of the box nothing
sends, and every send-permitting path (approval chains, allowlists, any future
auto-approve) is **human-configured**. The system is **fail-closed**: no
approval never decays into "send later"; an unapproved message waits forever.

## Consequences
- Only the human's configuration can loosen sending, never the agent or an injection.
- A message is released to the real upstream SMTP only after a full approval pass
  (see ADR 0004).
