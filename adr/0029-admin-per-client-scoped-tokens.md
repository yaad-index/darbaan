# ADR 0029: Admin API — per-client scoped, independently-revocable tokens

**Status:** Proposed (2026-07-09)

## Context

The operator admin API (ADR 0017) is a loopback-only, token-authenticated HTTP
surface that `serve` exposes; each approval or admin interface — the `darbaan`
CLI, the Telegram approval client, a future web admin UI, the agent pre-screener
— is a separate process that reaches the core only through it, holding **only**
an admin-API token (never the mail credentials).

Today that is a **single shared token** (`DARBAAN_ADMIN_TOKEN`): the `auth`
middleware constant-time-compares the presented bearer against the one configured
token, and every route is equally gated by it. So every interface holds the
**same, full-capability** credential.

As interfaces multiply, that shared token is a concentrated weak point:

- **No least privilege.** A read-only pre-screener that only needs to *list* the
  queue holds the same token that can *approve*, *reject*, *expose*, *drop*, and
  *release reconciliation*. Any holder has full power.
- **No independent revocation.** There is no way to revoke one interface's
  credential without rotating the single token — which breaks *every* other
  interface at once.

This ADR closes that gap while keeping the admin API's other invariants (ADR 0017
loopback-only; ADR 0002 least authority + operator-gated; ADR 0012 secrets
out-of-band). It was surfaced non-blocking in the ADR 0017 review (#59).

## Decision

Introduce **named admin clients**, each holding its own token and a
least-privilege **scope** set. The admin API resolves the presented token to a
client and authorizes the requested route against that client's scopes.

### Config shape

A new `admin_clients:` list beside `inboxes:` (ADR 0023) and `agents:`
(ADR 0027). Each entry is a `name` plus a `scopes:` set. The token is supplied
out-of-band via `DARBAAN_ADMIN_TOKEN_<NAME>` — the name uppercased with
non-alphanumerics mangled to `_`, the same env-prefix rule as the per-inbox /
per-agent secrets — and **never** in config (ADR 0012). This mirrors the
ADR 0027 multi-agent shape (a named principal + its grants, secret via env); an
`admincfg` package parses and validates it, reusing the existing config-bytes
path.

### Scopes

Capability-based and coarse. Every admin route (ADR 0017) maps to exactly one
required scope; the complete map, which is the authoritative contract:

| Method + route | Required scope |
|----------------|----------------|
| `GET /queue` | `queue:read` |
| `GET /queue/{id}` | `queue:read` |
| `POST /queue/{id}/approve` | `queue:decide` |
| `POST /queue/{id}/approve-as/{inbox}` | `queue:decide` |
| `POST /queue/{id}/reject` | `queue:decide` |
| `GET /holds` | `holds:read` |
| `POST /holds/{id}/expose` | `holds:decide` |
| `POST /holds/{id}/drop` | `holds:decide` |
| `GET /reconcile` | `reconcile:read` |
| `POST /reconcile/{inbox}/release` | `reconcile:release` |
| `GET /inboxes` | `inboxes:read` |

The scope vocabulary is therefore `queue:read`, `queue:decide`, `holds:read`,
`holds:decide`, `reconcile:read`, `reconcile:release`, `inboxes:read` —
extensible: a new route ships with its required scope, and any client granting
that scope reaches it.

A client's token grants exactly its listed scopes. Least-privilege examples:

- A **pre-screener** that only reads → the `*:read` scopes only; it cannot
  approve, reject, expose, drop, or release.
- The **Telegram client** → `queue:read` + `queue:decide` + `holds:read` +
  `holds:decide`, **plus `reconcile:read`** — required for the proactive
  cap-latch alert (`pollReconcile`, #149, shipped v0.11.0), which reads
  `GET /reconcile` every poll cycle; note it deliberately does **not** get
  `reconcile:release` (the latch alert points at the CLI release, so the Telegram
  credential cannot itself run the cap-bypassed purge).
- The **CLI** → all scopes.

### Auth resolution

The `auth` middleware resolves `Bearer <token>` to a client + scopes, then
authorizes the route's required scope. Resolution is **constant-time**: the
presented token is compared against every configured token with
`subtle.ConstantTimeCompare` and no early exit, and the same comparison work runs
on an unknown token (the miss path is equalized), so timing never reveals which —
or whether — a token matched. This is the same no-oracle discipline as ADR 0027's
`Verify`. An unrecognized token is `401 Unauthorized`; a recognized token that
**lacks** the route's scope is `403 Forbidden` (a distinct, clearer signal than a
blanket 401).

### Back-compat

Opt-in, with the default unchanged: **no `admin_clients:` → the single
`DARBAAN_ADMIN_TOKEN` is an implicit full-scope root client**, exactly today's
behavior, so existing single-token deployments are untouched. When
`admin_clients:` **is** configured, `DARBAAN_ADMIN_TOKEN` is retained as the
full-scope **root** (break-glass, and so ops/CLI keep working); scoped clients
are additive. Opt-in like `inboxes:` / `agents:`.

### Revocation

Because each client holds its **own** token, revoking one is dropping that client
from config (or unsetting its `DARBAAN_ADMIN_TOKEN_<NAME>`) and restarting
`serve`; every **other** client's token is unaffected — the "rotate for all"
problem is gone. Revocation is a deliberate operator act, consistent with
darbaan's read-only-at-runtime config (ADR 0012); it is **restart-scoped, not
live**.

### Alternative considered — runtime token management (rejected)

The fork is **config-defined tokens (A, chosen)** vs. a **runtime token-management
API (B, rejected)**: `serve` would expose privileged endpoints to *mint* and
*revoke* tokens live, persisting them (hashed) in a mutable store, so an operator
could revoke a credential without a restart.

(B) is rejected for v1:

- **It re-creates the very weak point #59 is shrinking.** A live mint endpoint is
  itself a concentrated, full-power surface (whoever can mint can grant any
  scope) — trading one concentrated token for a concentrated *capability*.
- **Bootstrapping.** Some credential must be allowed to mint others; defining and
  protecting that root-mint authority is its own problem, unsolved by the feature.
- **Mutable secret store.** It adds a new at-rest secret store to darbaan, against
  the ADR 0012 grain (secrets out-of-band, config read-only at runtime).
- **Marginal benefit here.** For an operator-run gate, a compromised-token
  response already implies an operator acting deliberately — and a `serve`
  restart is cheap. Live-no-restart revocation buys little over (A)'s
  drop-token-and-restart, which already delivers the issue's actual requirement
  (revoke one client without rotating the others).

(A) is the recommendation. **If there is a hard live-no-restart revocation
requirement, this is the fork to flip** — (B) would then be its own follow-up ADR
(a token store + a carefully-scoped mint/revoke surface + the bootstrap
authority), not folded into this one.

## Boundaries

- **No runtime token management** (no mint/revoke API, no token store) — tokens
  are config-defined, restart to apply.
- **No roles/RBAC hierarchy** — a flat scope set per client. A named-role
  convenience (e.g. `role: readonly` expanding to a scope set) could be config
  sugar in a later increment.
- **Loopback-only stands** (ADR 0017). Scoping is defense-in-depth *on top of*
  the network boundary, not a replacement for it.
- **Separate from ADR 0027 agent grants.** Admin scopes gate admin-API capability
  (an operator interface's power); ADR 0027 grants gate an agent's mail
  read/send. Different principals, different surface — they do not interact.
- **The full-scope root token is retained**; this ADR does not remove the
  single-token credential.

## Consequences

- Each interface holds a least-privilege credential; a read-only client cannot
  approve, reject, or release.
- One client's credential can be revoked without disrupting the others.
- More config + more env secrets to manage — mitigated by the opt-in back-compat
  (single-token deploys are unchanged).
- The `403` (wrong scope) vs `401` (bad/unknown token) split gives clearer
  operator diagnostics than a blanket 401.

## Slices

1. **`admincfg`** — parse/validate `admin_clients:` (unique names, env-prefix
   collision guard, known scopes) + the scope vocabulary constants + the
   route→scope map. No enforcement yet.
2. **Enforcement** — `auth` resolves token→client→scopes (constant-time) and
   authorizes per-route required scope (401 vs 403); the implicit full-scope root
   preserves back-compat.
3. **Wiring + docs** — `serve` builds the clients from config; config example +
   README; finalize this ADR (status → Accepted, README index row).
