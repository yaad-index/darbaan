# ADR 0017: Admin and approval interfaces are separate host processes over the local API

**Status:** Proposed (2026-06-26)

## Context

ADR 0001 established one local service hosting the protocol faces. ADR 0004 made
the approval pipeline pluggable and ADR 0005 made the agent pre-screener a
**compile-time** plugin selected by build tags — so adding an approval UI (web,
Telegram) or the AI pre-screener meant compiling it into the `serve` binary, and
the core could pull in a UI or AI dependency at build time.

ADR 0016 made the store canonical. The operator admin API (the localhost HTTP
surface `serve` exposes — list/show/approve/reject, token-authenticated, #52)
then made the `darbaan queue` CLI a **thin client** of a running `serve` rather
than a process that opens the stores directly.

Once that API exists, a compile-time plugin boundary for interfaces is no longer
the natural one. Any approval or admin interface can instead be its own process
that speaks to the local API. Maintainer direction (2026-06-26): build each
interface separately, not into the server; interfaces run on the host and expose
themselves to the world on top of the local API; the core stays localhost-only.

## Decision

**`serve` is the core and the only thing that touches the stores.** It hosts the
protocol faces (SMTP submit, IMAP read), owns the canonical store, the sender,
and the signer, and exposes the **localhost-only, token-authenticated admin
API**. It embeds no interface-specific or AI dependency.

**Every admin / approval interface is a separate host process that is a client
of the admin API.** The `darbaan queue` CLI is the first such client. The
Telegram bot and a future web admin UI are additional, independent
commands/processes — each shipped and versioned on its own, each bridging the
outside world (a chat, a browser) to the local API.

Consequences for earlier decisions:

- **Supersedes the compile-time mechanism of ADR 0004 and ADR 0005** (not their
  intent). Approval pluggability and the pre-screener stay; the *mechanism*
  moves from build tags to separate API clients. The approver build-tags are
  removed (#50).
- **Multi-party / multi-stage approval becomes a server-side policy over
  verdicts that clients POST**, not a compiled in-process chain. "Every required
  party must approve before release" is enforced by `serve` against verdicts
  arriving on the API.
- **The agent pre-screener becomes a client too** — a process that watches the
  queue over the API and posts a verdict — so the core never links an AI
  dependency (the original ADR 0005 goal, reached a different way).

## Boundaries and security

- The admin API stays **loopback-only / container-internal**, token-gated
  (ADR 0002; the #52 admin API). The core never exposes itself to the network.
- An interface that must be reachable from outside (a Telegram bot, a web UI)
  runs as its **own process** and is solely responsible for its own
  authentication and exposure. It reaches the core only through the local API,
  so a buggy or compromised interface cannot touch the stores except through the
  API's typed, authenticated surface.
- Credential isolation (ADR 0002) is unchanged: only the core holds the real
  mail credentials; an interface holds only an admin-API token.

## Consequences

- Interfaces are added or replaced without recompiling the core and without the
  core depending on their libraries.
- The stable seam is the admin API contract (its endpoints + token), which can
  grow — a verdict-policy endpoint, a push channel (#51) — without changing call
  sites.
- More moving parts at runtime (several processes) than a single binary; this is
  the deliberate trade for isolation and independent delivery.

## Follow-ups

- #50 — remove the approver build-tags; clients-over-API replace them.
- #51 — optional push (pub/sub) so the core notifies subscribed clients of a new
  trapped message instead of clients polling.
- The Telegram approval client is the first new interface built on this model.
