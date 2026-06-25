# ADR 0013: Go 1.24+, MIT license

**Status:** Accepted (2026-06-25)

## Context
We need a language and license for an open-source, embeddable, single-binary
proxy with compile-time plugin selection (ADR 0004).

## Decision
**Go 1.24+**, module `github.com/yaad-index/darbaan`. Layout: `cmd/darbaan/`
(thin CLI), `internal/` (private packages: listeners, sluice/queue, filter,
approver registry, backends, signer, audit), `pkg/` (public embeddable API),
`adr/`. Build-tag plugin pattern for compile-time approver/backend selection.
License: **MIT**.

## Consequences
- Single static binary, trivial to deploy on the local host.
- Compile-time plugin selection is idiomatic via build tags.
