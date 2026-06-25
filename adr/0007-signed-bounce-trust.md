# ADR 0007: Signed bounces as the trust anchor

**Status:** Accepted (2026-06-25)

## Context
Because rejections arrive as inbound mail (ADR 0006), a forged bounce is an
obvious attack: an outsider mails a fake MAILER-DAEMON telling the agent to
resend elsewhere with changes.

## Decision
Darbaan **signs every bounce** it issues (DKIM-style or a detached signature
header). Agents hold only the **verify (public) key**; Darbaan holds the
**signing (private) key**. An agent trusts **only** a rejection Darbaan itself
signed. Darbaan, being each agent's sole IMAP source, quarantines any external
mail posing as a bounce.

## Consequences
- Agents can confirm authenticity but never forge a bounce.
- The signing key is a critical secret (see ADR 0012).

## Amendment (2026-06-25, review)
**One mechanism + key distribution.** Darbaan signs bounces using **DKIM**
(RFC 6376) over a dedicated signing domain/selector — email-native and
verifiable with standard tooling (chosen over an ad-hoc detached header).
**Key distribution:** Darbaan holds the private key; each agent is provisioned
**out of band** with Darbaan's public key **pinned** at setup and verifies every
bounce against it. Key rotation is an operator action that re-pins.
