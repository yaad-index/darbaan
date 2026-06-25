# ADR 0009: Pluggable backends with capability negotiation

**Status:** Accepted (2026-06-25)

## Context
Plain IMAP/SMTP is universal but limited; providers like Gmail expose richer
features (labels, server-side search) we want to use when available.

## Decision
Upstream connectivity is a **pluggable backend interface**. v1 ships **two**: a
**generic IMAP/SMTP** baseline and a **Gmail** provider backend. Backends
**advertise capabilities**; the rule/feature layer checks capability before use,
so a Gmail-label rule runs on Gmail and **gracefully degrades** (no-op or
load-time warning) on the generic backend. Rules degrade, they do not break.

## Consequences
- New providers (Outlook/Graph, JMAP) are added behind the same interface later.
- Features are written once against capabilities, not per-provider forks.

## Amendment (2026-06-25, review)
**Graceful degradation does not apply to safety rules.** A rule may be marked
**`safety: true`**. A safety rule must **never** silently degrade: if the active
backend cannot enforce it (capability missing), Darbaan **fails closed** — it
refuses to expose the affected messages (or errors at load) rather than no-op.
Only **non-safety** rules (noise/convenience) degrade to a no-op with a warning.
A capability gap can never silently switch off a security-relevant filter.
(Supersedes the unqualified "rules degrade, they do not break" above.)
