# ADR 0014: Prefer established libraries over reinventing

**Status:** Accepted (2026-06-25)

## Context
Darbaan touches protocols and cryptography: SMTP and IMAP (server and client
sides), MIME / `message/rfc822`, DSN bounce generation, DKIM-style signing and
verification, YAML rules, and secret encryption at rest. Hand-rolling protocol
or crypto code is error-prone, and bugs there are security bugs.

## Decision
**Build on well-established, maintained, MIT-compatible external libraries as
much as possible.** Specifically, do **not** hand-roll protocol or cryptographic
code — use vetted libraries for IMAP/SMTP, MIME/message parsing, DSN, DKIM
sign/verify, YAML, and encryption (e.g. age/sops or an OS keyring). Reserve
in-house code for Darbaan's **own** logic: the sluice, the approver registry and
pipeline, routing, policy, the audit log. Prefer the standard library where it
suffices; reach for a vetted third-party library rather than reimplement; but
avoid trivial micro-dependencies that add supply-chain surface for little gain.

## Consequences
- Less protocol/crypto risk; faster to a correct v1.
- Notable dependency choices are themselves decisions and should be recorded.
- All dependencies must be license-compatible with MIT.
- We accept some supply-chain surface as the price of protocol/crypto correctness,
  and keep that surface deliberate rather than incidental.
