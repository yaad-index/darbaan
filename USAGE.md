# Working with Darbaan (the mail gate)

Darbaan is a **mail-gate proxy**. Instead of talking to your email provider
directly, your agent reads inbound mail and submits outbound mail **through
Darbaan** over standard **IMAP** and **SMTP**. Darbaan holds the real mailbox
credentials and enforces policy in front of them, so the agent only ever holds
*Darbaan* credentials — never the real mailbox.

Two things define how you work with it:

- **Reading is gated and read-only.** You read a synced view of the real mailbox.
- **Sending is default-deny.** Every message you submit is **held for human
  approval** — a successful submit means "queued", not "delivered". Rejections
  come back to you as a **signed bounce**.

---

## Connecting

Darbaan exposes two agent-facing services. Both use **STARTTLS** and require the
**agent login** (a username + password issued by the deployment — not the real
mailbox credentials):

| Face | Port | Use |
|---|---|---|
| IMAP | `1143` | read mail, label mail, read bounces |
| SMTP | `1465` | submit mail for sending |

- Connect plaintext, issue `STARTTLS`, then authenticate (`AUTH PLAIN`).
- On a trusted deployment Darbaan may present a **self-signed certificate**; a
  client on the trusted network skips certificate verification.
- A separate admin API exists for the operator only — it is **not** reachable by
  the agent and is not needed for any of the steps below.

---

## Reading mail (IMAP)

- Darbaan serves the mailbox as a single **`INBOX`** — a synced, recency-bounded
  view of received mail. Select it and use plain IMAP (`SEARCH`, `FETCH`).
- **It can be a filtered view.** The operator may configure rules that hide some
  messages, or hold them back pending review, before they ever reach you. So your
  `INBOX` can intentionally contain *fewer* messages than the underlying mailbox —
  that is by design (gated), not lost mail. Don't treat a smaller-than-expected
  inbox as an error.
- **Standard IMAP only.** Do not rely on provider-specific extensions (Gmail raw
  search, All-Mail folders, etc.); they are not available through the gate.
- **Listing is cheap.** Envelopes and headers are synced eagerly; a message
  **body is fetched on first read** and then cached. Listing the inbox downloads
  no bodies.
- The synced **store is canonical** — treat the face as read-only for content.
- **Tracking what you have already processed:** keep your *own* marker. The
  reliable pattern is a **UID high-water-mark** (remember the highest UID you
  have handled; next run, process only `UID > high-water`), or a local record of
  handled `Message-ID`s. Do not depend on server-side flags/keywords persisting
  as your processed-state.

A typical fetch loop: `SELECT INBOX` → `UID SEARCH ALL` → process the UIDs above
your high-water → `UID FETCH <n> (RFC822)` → advance the high-water.

---

## Labeling mail

- Apply a label with a **standard IMAP keyword**: `UID STORE <n> +FLAGS (mylabel)`
  (remove with `-FLAGS`).
- On a **Gmail-backed** deployment these keywords map to real **Gmail labels** —
  searchable in Gmail as `label:mylabel`. The local store is canonical; the
  provider label is an eventually-consistent replica.
- Use labels for triage/organization you want reflected in the real mailbox
  (e.g. marking something handled, flagging it for a human). Keep your own
  processed-state separately (see above) rather than reading labels back as
  control state.

---

## Sending mail (and the approval gate)

Submitting is ordinary SMTP — `STARTTLS`, authenticate, then `MAIL FROM` /
`RCPT TO` / `DATA` (or your SMTP client's `send_message`). **But:**

1. **Every submission is held, not sent.** Darbaan is default-deny: a successful
   submit means the message is **queued pending approval**, NOT delivered. Treat
   a send as *asynchronous*.
2. **A human operator approves or rejects** each held message out-of-band (e.g. a
   queue CLI, or a phone approval client). Your agent does not approve its own
   mail — that is the whole point of the gate.
3. **Outcome:**
   - **Approved** → Darbaan delivers via the upstream provider (and signs it).
   - **Rejected** → you receive a **bounce** (next section). Nothing was sent.

Design senders accordingly: submit, then expect *either* silent delivery (on
approval) *or* a bounce (on rejection) — never assume immediate delivery, and do
not retry blindly on "no confirmation".

> Some deployments run the upstream sender in **stub** mode (it delivers nothing
> even after approval) until real delivery is deliberately switched on. If
> approved mail is not arriving, check whether the deployment has enabled real
> sending.

---

## Bounces (handling rejections)

When a held message is **rejected** (or otherwise can't be delivered), Darbaan
emits a **DSN bounce** — a standard delivery-status-notification message — and
you **read it back over IMAP**, in your inbox, like any other mail.

- **The bounce is DKIM-signed by Darbaan** (its own signing selector + domain).
  This is what makes a bounce *trustworthy*: **verify the DKIM signature** against
  Darbaan's signing identity before acting on it. A bounce is a security-relevant
  message (it tells you a send failed); a forged or unsigned "bounce" that does
  not verify against Darbaan's key should **not** be trusted or acted on.
- **Match it to your sent message.** The DSN echoes the original message's
  headers (e.g. `Message-ID`), so you can tie the bounce back to the specific
  submission it concerns.
- **Read the reason.** The DSN carries the status/reason for the failure. Use it
  to decide what to do — surface to a human, fix and resubmit, or drop — rather
  than silently re-sending the same message (which will just be held again).

---

## Quick reference

| Goal | How |
|---|---|
| Read new mail | IMAP `1143` → `SELECT INBOX` → fetch `UID > high-water` |
| Label mail | IMAP `UID STORE <n> +FLAGS (label)` |
| Send mail | SMTP `1465` → submit → **held for approval** |
| Confirm a send | it's async: delivery is silent; a **signed bounce** means rejected |
| Trust a bounce | verify its **DKIM signature** against Darbaan's identity first |

Never hardcode the agent credential — load it from your deployment's
configuration/secret store.
