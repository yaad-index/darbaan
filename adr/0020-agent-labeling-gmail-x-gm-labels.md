# ADR 0020: Agent labeling via IMAP keywords (with Gmail X-GM-LABELS mapping)

**Status:** Proposed (2026-06-27)

## Context

The inbound sync (ADR 0019) gives the agent read-through access to its mailbox. The
maintainer wants the agent to **label** mail as it works — both rule-driven and from
its own judgment in the moment (e.g. mark a message `useless`, `handled`,
`suggest-delete`) — so labels become a triage and signalling surface, and they should
round-trip to the real provider so the maintainer sees them.

Send (the outbound sluice, ADR 0003) and the deferred human-gated delete stay
fail-closed because they are outbound/destructive. **Labels are different:
non-destructive and reversible**, so they do not need the gate.

Darbaan is **backend-agnostic** (ADR 0009, capability negotiation): the sync and read
face use only standard IMAP, so it must work against any IMAP provider. Labeling must
not couple Darbaan to Gmail. The universal IMAP mechanism for per-message labels is
**keywords** (custom flags, RFC 3501), supported by every IMAP server. Gmail's
`X-GM-LABELS` is a richer, Gmail-only extension that surfaces the same intent as
first-class Gmail labels.

## Decision

**Agent labeling is built on standard IMAP keywords (universal), with Gmail
`X-GM-LABELS` as an optional mapping layer chosen by capability negotiation.**

- **Universal core — keywords.** The read face accepts custom keywords via
  `STORE [+|-]FLAGS (\\keyword)` and serves them on `FETCH FLAGS`. The agent labels by
  setting keywords; this works against **any** IMAP backend. Label changes are written
  through to the upstream as standard keyword `STORE` over a read-write session.
- **Read.** The sync pulls each message's keywords (and, on Gmail, its labels) into
  the inbound record metadata; the read face serves them so the agent sees existing
  labels.
- **Write-through.** A keyword change updates the stored metadata **and** applies to
  the upstream mailbox. This is a deliberate, **narrow exception** to read-only-upstream
  (ADR 0019): the sync stays read-only for message content and for deletes/expunge,
  but agent **label** changes write through, precisely because labels are
  non-destructive and reversible.
- **Gmail mapping (enhancement, capability-negotiated).** When the backend advertises
  `X-GM-EXT-1`, Darbaan maps keywords ↔ `X-GM-LABELS` so the agent's keyword `useless`
  becomes a real Gmail label `useless`, visible in Gmail's UI, and existing Gmail
  labels surface as keywords. On non-Gmail backends this layer is simply absent and
  labeling runs on plain keywords with no loss of function.
- **Agent-direct (no gate).** Unlike send (sluice) and delete (deferred human-gate),
  labeling is agent-direct — no approval needed, because a label is safe and undoable.

## Boundaries / non-goals (this increment)

- **Labels only.** No content writes, no delete/expunge write-through. Deletion and
  its human-gated feedback model (hide → judge → delete or return-with-note) is
  deferred to its own ADR at the maintainer's call (2026-06-27).
- **Gmail mapping is an enhancement, never a requirement.** The keyword core is the
  contract; the `X-GM-LABELS` mapping is selected by capability negotiation (ADR 0009)
  and degrades to absent on non-Gmail. Darbaan works against any IMAP backend.
- **No structured filter yet.** Rule-based allow / hide / hold (ADR 0008) is a
  separate increment; this is agent-initiated labeling, not rule evaluation.

## Consequences

- The agent gains real triage power: label/flag mail (`useless`, `handled`,
  `suggest-delete`, …) on any backend, and on Gmail those labels are first-class and
  visible to the maintainer.
- The upstream becomes write-capable for **labels only** — the credential-isolation
  boundary (ADR 0002) now permits a narrow label write (keyword STORE, or its Gmail
  mapping), still no content/delete writes. The label-write session is separate from
  the read-only sync session.
- No Gmail coupling in the core; the Gmail mapping is isolated behind capability
  negotiation, consistent with the pluggable-backend design (ADR 0009).
- Lays groundwork for the deferred human-gated delete — a `suggest-delete` label is
  the agent's half of that future flow.

## Follow-ups

- **Human-gated delete** + its store-canonical feedback model: agent `suggest-delete`
  hides the message pending judgment; on approve it is deleted, on reject it returns
  to view carrying a synthetic `X-Darbaan-Note` header with the keep reason. The
  message state (read over IMAP), not a bounce, is the feedback channel. Deferred
  2026-06-27.
- Structured inbound filter rules (ADR 0008).

Relates to ADR 0001, 0002, 0009, 0016, 0019.
