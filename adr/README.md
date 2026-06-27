# Architecture Decision Records

Darbaan records its significant decisions as ADRs. Each file is one decision:
its context, the decision, and the consequences. ADRs are immutable once
Accepted — to change one, add a new ADR that supersedes it.

These records (0001–0016) capture the v1 design, locked 2026-06-25 and amended
through 2026-06-26 (maintainer review).

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
| [0013](0013-go-and-mit.md) | Go (latest stable), MIT license |
| [0014](0014-prefer-established-libraries.md) | Prefer established libraries over reinventing |
| [0015](0015-storage-abstraction.md) | Abstract storage behind interfaces; config-selected backend |
| [0016](0016-store-canonical-translation-faces.md) | Store-canonical architecture; protocol faces are translation adapters |
| [0017](0017-interfaces-as-clients-over-local-api.md) | Admin and approval interfaces are separate host processes over the local API |
| [0018](0018-tiered-storage-metadata-kv-content-filesystem.md) | Tiered storage: metadata in the KV store, message content on the filesystem |
| [0019](0019-inbound-sync-store-canonical-lazy-no-filter.md) | Inbound mailbox sync: store-canonical incremental pull, lazy content, no filter (v1) |
