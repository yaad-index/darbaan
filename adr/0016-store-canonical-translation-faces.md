# ADR 0016: Store-canonical architecture; protocol faces are translation adapters

**Status:** Accepted (2026-06-26)

## Context
Darbaan must filter, hold (hold-for-human), and serve both Darbaan-generated
messages (bounces) and, later, upstream inbound mail. A live IMAP pass-through
that selectively hides messages is a UID / sequence-number / state hazard and
hard to get right.

## Decision
The **store is the single source of truth.** Each protocol face is a thin
**translation adapter** over the store, never a live proxy:
- The **SMTP submit** face writes submissions into the store (the trap, ADR 0003).
- The **IMAP read** face reads from the store and translates to IMAP.
- Future faces (JMAP, a local API) are additional adapters over the same store.

This refines the word "proxy" in ADR 0001 (adapter-over-store, not pass-through).

**MVP scope:** the IMAP read face serves **only Darbaan-generated messages** (the
signed bounces / notifications, ADR 0006/0007); it needs **no upstream inbound
fetch**. Syncing real upstream inbound mail into the store and filtering it
(ADR 0008) is a **later layer**, served through the same adapter (post-MVP).

## Consequences
- Filtering and hold-for-human are tractable on owned data; there is no
  live-proxy IMAP state to manage.
- New protocols are new adapters, not new proxies.
- Costs: sync lag (for the later upstream layer) and storing fetched mail
  (at-rest encryption, ADR 0012).
- Bounces (ADR 0006) are the first content the read face serves, enabling a
  minimal end-to-end MVP (SMTP in, IMAP out for bounces) with no upstream read
  integration.
