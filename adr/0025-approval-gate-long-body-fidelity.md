# ADR 0025: Approval gate — full-body fidelity for long messages (.txt attachment)

**Status:** Proposed (2026-06-29)

## Context

The Telegram approval client (`internal/telegram`) renders a held message for the
operator to review before release: headers (From / To / Cc), hidden-recipient
warnings, the attachment list (each uploaded for inspection), and the decoded
**text body** inline (`body.go: bodyText`). The decision keyboard (Approve /
Reject) acts on that view (ADR 0004/0017).

Telegram caps a text message at **4096 UTF-16 units** (and a media caption at
1024). A long email body (a deep reply chain, a newsletter) **overflows that cap**,
so the inline body is truncated by Telegram. The capture is **not** the problem —
the sluice stores the full raw message and `bodyText` decodes all of it — the
problem is **review fidelity**: the operator can be shown a truncated body and
approve it believing they saw the whole thing. The full thread must be reviewable
at the gate.

## Decision

When the body is too long to render inline, the Telegram client **attaches the
full body as a `.txt` document to the same approval message**, and the inline
preview is explicitly marked as truncated.

### Specifics

- **Threshold:** if the rendered body would push the notification over Telegram's
  per-message limit, the body is **moved to an attached `.txt`** rather than
  truncated silently. (Implementation picks the exact rune budget, leaving room for
  the header/attachment-list block that shares the message.)
- **Body only, not the `.eml`.** The attachment is the **decoded text body**
  (`bodyText` output) — the headers and metadata are already shown in the message,
  so the operator does not need the full raw `.eml`. (Operator confirmed: body
  only, `.txt`, no PDF — PDF would need a rendering dependency.)
- **Clearly the original message, not an email attachment.** `body.go` already
  uploads the email's *own* attachments (the exfiltration-vector list). The
  full-body `.txt` must be unmistakably distinct from those: a fixed, descriptive
  filename (e.g. `original-message-body.txt`) and a caption that says it is the
  **full text of the message under review**, not a file the message carried. It is
  attached to / replied onto the **same** approval message so the operator sees it
  in context with the Approve / Reject buttons.
- **Truncation is never silent.** When the body is offloaded, the inline preview
  ends with an explicit marker (e.g. `… [truncated — full body attached as
  original-message-body.txt]`) so the operator knows the inline text is partial and
  the decision should be made against the attachment.

### Why the client, not the store

The held payload is already complete (sluice stores `Raw`; `bodyText` decodes the
whole body). This is purely a **delivery-fidelity** fix in the approval client
(ADR 0017: interfaces are clients over the local API) — no store, admin-API, or
filter change.

## Boundaries / non-goals

- **No PDF / rich rendering** (would add a dependency); plain `.txt` of the text
  body is the deliverable.
- **No raw `.eml` export** here — headers/metadata are already in the message; a
  full-raw export is a separate need if it ever arises.
- **HTML-only bodies:** when a message has no `text/plain` part, `bodyText` already
  falls back to nested text; if it yields nothing, the `.txt` is empty/absent and
  the existing attachment list still lets the operator open the raw parts. A
  dedicated HTML-to-text path for the offloaded body is a possible follow-up, not
  required here.

## Consequences

- The operator can always review the **complete** message body at the gate,
  regardless of length, and is never silently shown a truncated view.
- The full-body `.txt` is visually distinct from the email's own attachments, so it
  cannot be mistaken for message-carried content.
- Scope stays inside `internal/telegram`; the contract with the admin API and store
  is unchanged.

## Follow-ups

- HTML-only → text extraction for the offloaded body, if HTML-only mail proves
  common at the gate.
- The sender-override at the approval gate (Approve / **Change** sender) is a
  **separate** approval-client change tracked with the multi-inbox ADR (it needs
  the configured per-inbox identity set); it is intentionally not in this ADR.

Relates to ADR 0004, 0017.
