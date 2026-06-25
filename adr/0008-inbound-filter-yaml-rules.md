# ADR 0008: Inbound filter — declarative YAML rules

**Status:** Accepted (2026-06-25)

## Context
On read, Darbaan should hide noise and reduce attack surface, and sometimes ask
the human whether the agent may see a message at all.

## Decision
Inbound filtering uses **declarative YAML** rules, matched on fields (from, to,
subject, label, header), evaluated **top-down, first match wins**. v1 actions:
**hide | allow | hold-for-human**. `hold-for-human` is the inbound mirror of the
outbound trap: hold the message and ask the human "expose this to the agent?",
reusing the approver plumbing (ADR 0004). **Redaction** (altering contents) is
deferred post-v1.

## Consequences
- The rule engine stays small and auditable.
- Inbound filtering is privacy/noise/surface control; it does **not** stop an
  injection from an allowed sender — the outbound trap (ADR 0003) does.

## Amendment (2026-06-25, review)
**Default action on no match: `allow`** (the agent sees the message). Rationale:
inbound reading is recoverable and the outbound trap (ADR 0003) is the real
containment, so hiding is opt-in. The no-match default is **configurable** — an
operator wanting a stricter posture can set it to `hold-for-human`. The default
is always explicit in config, never implicit.
