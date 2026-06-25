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
