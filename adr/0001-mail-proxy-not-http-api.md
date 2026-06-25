# ADR 0001: A mail proxy over IMAP/SMTP, not an HTTP API

**Status:** Accepted (2026-06-25)

## Context
Agents need to read and send email under policy. We could expose a bespoke
HTTP API, or speak the protocols mail already uses.

## Decision
Darbaan is a **proxy** that agents talk to over standard **IMAP** (read) and
**SMTP** (send). It is not an HTTP service. Behind it sit the real mailboxes.

## Consequences
- Existing mail tooling works unchanged.
- Rejections can use real email semantics (see ADR 0006), not custom error codes.
- One local service hosts both the IMAP face and the SMTP face.
- Public-library boundary follows Go convention: `pkg/` public API, `internal/`
  private, thin CLI in `cmd/darbaan` (see ADR 0013).
