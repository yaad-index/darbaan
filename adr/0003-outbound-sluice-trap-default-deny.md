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

## Amendment (2026-09-25): the release Consequence is narrowed by ADR 0034
**The second Consequence above no longer holds as written.** ADR 0034 defines an
additional send-permitting path; its conditions and its boundaries are stated
there, and that ADR is the reference rather than this note. The Consequence is
narrowed to: a message is released after a full approval pass (ADR 0004) or
through a configured send-permitting path.

**The Decision is unchanged.** It already requires every send-permitting path to be
human-configured, and names allowlists among them, so the path ADR 0034 defines is
an instance of this Decision rather than an exception to it. Default-deny and
fail-closed are unchanged.
