# ADR 0013: Go (latest stable), MIT license

**Status:** Accepted (2026-06-25)

## Context
We need a language and license for an open-source, embeddable, single-binary
proxy with compile-time plugin selection (ADR 0004).

## Decision
**Go 1.26** (track the latest stable release), module `github.com/yaad-index/darbaan`. Layout: `cmd/darbaan/`
(thin CLI), `internal/` (private packages: listeners, sluice/queue, filter,
approver registry, backends, signer, audit), `pkg/` (public embeddable API),
`adr/`. Build-tag plugin pattern for compile-time approver/backend selection.
License: **MIT**.

## Consequences
- Single static binary, trivial to deploy on the local host.
- Compile-time plugin selection is idiomatic via build tags.

## Amendment (2026-06-26)
Pin to **Go 1.26**, not 1.24. Go 1.24 fell out of support when 1.26 shipped
(Go supports the latest two releases); latest stable at time of writing is
go1.26.4. Policy: **track the latest stable Go**, bump `go.mod` as new releases land.
