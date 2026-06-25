# Architecture Decision Records

Darbaan records its significant decisions as ADRs. Each file is one decision:
its context, the decision, and the consequences. ADRs are immutable once
Accepted — to change one, add a new ADR that supersedes it.

These initial records (0001–0013) capture the v1 design locked on 2026-06-25.

| ADR | Title |
|---|---|
| [0000](0000-record-architecture-decisions.md) | Record architecture decisions |
| [0001](0001-mail-proxy-not-http-api.md) | A mail proxy over IMAP/SMTP, not an HTTP API |
| [0002](0002-policy-in-a-separate-box-credential-isolation.md) | Policy in a separate trusted box; credential isolation |
| [0003](0003-outbound-sluice-trap-default-deny.md) | The outbound sluice trap, fail-closed and default-deny |
| [0004](0004-pluggable-approval-pipeline.md) | Pluggable, multi-level approval pipeline |
| [0005](0005-agent-prescreener-plugin-risk-routing.md) | Agent pre-screener as a compile-time plugin; risk routing |
| [0006](0006-rejection-as-async-dsn-bounce.md) | Rejection modelled as an asynchronous DSN bounce |
| [0007](0007-signed-bounce-trust.md) | Signed bounces as the trust anchor |
| [0008](0008-inbound-filter-yaml-rules.md) | Inbound filter: declarative YAML rules |
| [0009](0009-pluggable-backends-capability-negotiation.md) | Pluggable backends with capability negotiation |
| [0010](0010-multi-mailbox-v1-multi-agent-deferred.md) | Multi-mailbox in v1; multi-agent deferred |
| [0011](0011-append-only-audit-log.md) | Append-only audit log |
| [0012](0012-deployment-and-secrets-at-rest.md) | Deployment and secrets at rest |
| [0013](0013-go-and-mit.md) | Go 1.24+, MIT license |
| [0014](0014-prefer-established-libraries.md) | Prefer established libraries over reinventing |
