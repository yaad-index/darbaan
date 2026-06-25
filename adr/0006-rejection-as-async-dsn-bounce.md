# ADR 0006: Rejection modelled as an asynchronous DSN bounce

**Status:** Accepted (2026-06-25)

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
