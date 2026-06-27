# ADR 0004: Pluggable, multi-level approval pipeline

**Status:** Accepted (2026-06-25)

## Context
Approval may come from a person via different surfaces, or from an automated
check. We do not want the gate wired to a single mechanism.

## Decision
Approvers implement one contract: `(message + metadata) -> verdict`. A web UI, a
Telegram bot, a chat react, or an agent are all implementations. Approvers are
selectable at **runtime and compile time** (Go build tags, blank-import
registry), so a binary can ship with only the approvers wanted. Chaining gives
**multi-level** approval (every stage must pass). **Edit-before-release** is a
per-approver capability: an approver that supports it (web) may edit a draft
inline and release; others only approve/reject. Editing is **human-only**;
agent approvers never edit.

## Consequences
- New approval surfaces are added without touching the core.
- The audit log keeps both the agent's original draft and any human-edited
  version (see ADR 0011).

## Amendment (2026-06-25, review)
**Approver timeout = fail-closed.** If no approver acts within a configured
window, the message is **not** sent; it stays queued. A timeout never
auto-sends, consistent with default-deny (ADR 0003). Operators may configure
escalation or an explicit expiry-to-rejected (which then bounces per ADR 0006),
but the default on timeout is "keep waiting," never "send."

## Amendment (2026-06-27): compile-time selection removed
The "compile time (Go build tags)" half of approver selection is gone. ADR 0017
made the interfaces runtime clients over the local admin API, and the last build
tag (`no_manual_approver`) was dropped (#50). Approvers are now **always
compiled in** and selected purely at **runtime** via the configured chains
(`approval-strict` / `approval-light`). The blank-import registry stays; only the
build-tag gating is removed. The chain remains fail-closed — a path with no
approver registered approves nothing.
