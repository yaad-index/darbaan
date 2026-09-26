# ADR 0006: Rejection modelled as an asynchronous DSN bounce

**Status:** Accepted (2026-06-25); amended 2026-09-26 (see the end)

## Context
Approval is asynchronous; a human may take hours. You cannot hold an SMTP
connection open that long, and a custom async API would break ADR 0001.

## Decision
Darbaan accepts the submission, then if the message is rejected it delivers a
**MAILER-DAEMON-style bounce** to the agent's inbox, original attached as
`message/rfc822`, reason in the body, using real **DSN** status codes (RFC 3464):
**4.x.x transient** = revise and resubmit; **5.x.x permanent** = drop, do not
retry. A **retry cap** bounds fix-and-resubmit loops. Every **permanent (5xx)**
rejection is a **security signal**, logged and surfaced to the operator. The
rejection reason always originates from Darbaan/the approver and **never echoes
the attacker's email text**.

## Consequences
- The agent's existing read loop handles rejections; no custom protocol.
- The correction loop closes naturally for transient rejections.

## Amendment (2026-09-26): the retry cap's correlation key

Decision on items A16 and C11 of #237; text above stays as written (ADR 0037).

The retry cap above bounds fix-and-resubmit loops but names no way to tell that a
submission is a retry, so as written it cannot be implemented, and it is not. It is
implemented rather than removed, because the loop it guards against, an agent
resubmitting a bounced message indefinitely, is real:

- **The correlation key is the original message's queue id**, carried on the
  resubmission as a lineage field set when a bounced message is resubmitted.
- **The retry counter lives on the queue record** of that lineage.
- **Past N resubmissions, a resubmission is auto-rejected.** N defaults to 3 and is
  configurable.

The lineage field and the cap follow this amendment in code.

## Amendment (2026-09-26): what the retry cap counts

Scope of the amendment above; text above stays as written (ADR 0037).

The lineage field is set by Darbaan, from the thread reference, not by the agent:
every bounce carries a Message-ID Darbaan controls that names the rejected message's
queue id, and a submission whose `In-Reply-To` or `References` names such a bounce is
a resubmission of that message, counted against its lineage's original. A reference
to an unknown message, or to another agent's message, gives no lineage, so one agent
cannot spend another's retries.

**The cap therefore bounds only resubmissions that reference the bounce.** A fresh,
unthreaded message is not counted, even if it resends the same content. Catching
those would need a heuristic key (same sender, recipients and subject within a
window), which can misfire on a legitimate second message; that is a separate
decision, to be taken if unthreaded loops are seen.
