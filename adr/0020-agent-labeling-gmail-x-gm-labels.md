# ADR 0020: Agent labeling over Gmail X-GM-LABELS (read + write-through)

**Status:** Proposed (2026-06-27)

## Context

The inbound sync (ADR 0019) gives the agent read-through access to its mailbox. The
maintainer wants the agent to **label** mail as it works — both rule-driven and from
its own judgment in the moment (e.g. mark a message `useless`, `handled`,
`suggest-delete`) — so labels become a triage and signalling surface. Crucially the
labels must round-trip to the real provider, so the maintainer sees them in Gmail.

Send (the outbound sluice, ADR 0003) and the deferred human-gated delete stay
fail-closed and human-approved because they are outbound/destructive. **Labels are
different: non-destructive and reversible**, so they do not need the gate. The
maintainer accepted a Gmail-specific protocol extension to make this Gmail-native
(2026-06-27).

## Decision

**Darbaan's IMAP read face implements Gmail's `X-GM-LABELS` extension, and agent
label writes propagate upstream to Gmail.**

- **Capability.** The read face advertises `X-GM-EXT-1` and supports
  `FETCH X-GM-LABELS` and `STORE [+|-]X-GM-LABELS`.
- **Read.** The sync pulls each message's Gmail labels (FETCH `X-GM-LABELS`) into the
  inbound record metadata; the read face serves them, so the agent sees existing
  labels.
- **Write-through.** When the agent STOREs a label change, Darbaan updates the stored
  metadata **and** applies the change to the upstream Gmail mailbox (UID STORE
  `X-GM-LABELS` over a read-write upstream session). This is a deliberate, **narrow
  exception** to the read-only-upstream rule (ADR 0019): the sync stays read-only for
  message content and for deletes/expunge, but agent **label** changes write through,
  precisely because labels are non-destructive and reversible.
- **Agent-direct (no gate).** Unlike send (sluice) and delete (deferred human-gate),
  labeling is agent-direct — no approval needed, because a label is safe and undoable.

## Boundaries / non-goals (this increment)

- **Labels only.** No content writes, no delete/expunge write-through. Deletion and
  its human-gated feedback model (hide → judge → delete or return-with-note) is
  deferred to its own ADR at the maintainer's call (2026-06-27).
- **Gmail-specific.** `X-GM-LABELS` is a Gmail extension; a generic IMAP backend maps
  labels to keywords/folders or no-ops under capability negotiation (ADR 0009). v1
  targets the Gmail backend.
- **No structured filter yet.** Rule-based allow / hide / hold (ADR 0008) is a
  separate increment; this is agent-initiated labeling, not rule evaluation.

## Consequences

- The agent gains real triage power: label/flag mail (`useless`, `handled`,
  `suggest-delete`, …), visible to the maintainer in Gmail.
- The upstream becomes write-capable for **labels only** — the credential-isolation
  boundary (ADR 0002) now permits a narrow label write, still no content/delete
  writes. The upstream label session is separate from the read-only sync session.
- Gmail coupling for the label path; other backends degrade to keyword/folder
  mapping or no-op.
- Lays groundwork for the deferred human-gated delete — a `suggest-delete` label is
  the agent's half of that future flow.

## Follow-ups

- **Human-gated delete** + its store-canonical feedback model: agent `suggest-delete`
  hides the message pending judgment; on approve it is deleted, on reject it returns
  to view carrying a synthetic `X-Darbaan-Note` header with the keep reason. The
  message state (read over IMAP), not a bounce, is the feedback channel. Deferred
  2026-06-27.
- Structured inbound filter rules (ADR 0008).
- Generic-backend label mapping (keywords/folders) under capability negotiation
  (ADR 0009).

Relates to ADR 0001, 0002, 0009, 0016, 0019.
