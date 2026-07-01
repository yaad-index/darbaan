# ADR 0027: Multi-agent tenancy — per-agent logins, grants, and per-principal mailbox naming

**Status:** Accepted (2026-07-01)

## Context

ADR 0010 chose **multi-mailbox + single-agent** for v1 and deferred multi-agent,
sketching it so v1 would not foreclose it. ADR 0023 then realized multi-inbox: N
inboxes in one Darbaan, each with its own backend, identity, filters, and
visibility — but still **one agent principal that sees every inbox** read+send.
Both ADRs left an inbox id threaded through storage and the audit log
specifically so a per-agent permission model could be keyed on it later without
reshaping data.

This ADR is that model. It **supersedes the deferred multi-agent sketch in ADR
0010** and builds directly on ADR 0023's inbox as the first-class unit. The
motivating shape: several agent principals share one Darbaan, each seeing **only**
the inboxes it is granted, in the direction(s) it is granted — one agent may read
and send a shared team inbox while another only reads it, and a third sees a
private inbox neither of the first two can address. Privacy is by **omission**: an
inbox an agent is not granted does not exist for that agent.

## Decision

**An agent becomes a first-class, named config principal with its own login
credentials and an explicit per-inbox grant list. Authentication resolves the
login to an agent; that agent's grants are the session principal and gate every
read and send. The mail-owner store key is decoupled from the login principal so
several agents can share one inbox.**

### Config shape

A new `agents:` list sits beside `inboxes:` (ADR 0023). Each agent is a login
name, a password supplied **only** via a secret env var (never in the config
file, ADR 0012), and a list of grants:

```yaml
inboxes:
  - name: inbox-a
    identity: a@inbox-a.example
    backend: { ... }
  - name: inbox-b
    identity: b@inbox-b.example
    backend: { ... }

agents:
  - name: agent-a
    # password from DARBAAN_AGENT_AGENT_A_PASSWORD — never in config (ADR 0012)
    default_inbox: inbox-a          # one of this agent's granted inboxes; shown as IMAP INBOX
    grants:
      - { inbox: inbox-a, access: [read, send] }
      - { inbox: inbox-b, access: [read] }        # read-only on the shared inbox
  - name: agent-b
    default_inbox: inbox-b
    grants:
      - { inbox: inbox-b, access: [read, send] }
```

- **Password**: the secret env var name is derived from the login,
  `DARBAAN_AGENT_<NAME>_PASSWORD` (`<NAME>` upper-cased, non-alphanumerics to
  `_`). This generalizes today's single `DARBAAN_AGENT_PASS` to a per-agent map.
  Consistent with ADR 0012, no password is ever written to the config or disk.
  Because the derivation collapses characters (`a-b` and `a_b` both normalize to
  `A_B`), the config validator **rejects any two agents whose normalized env-var
  names collide**, not merely whose raw names differ — otherwise two agents would
  silently share one password variable.
- **Grants**: a grant names an inbox and an `access` set drawn from `{read,
  send}`. **Sharing an inbox is expressed by listing it under more than one
  agent**; there is no separate sharing construct. **Privacy is omission** — an
  inbox absent from an agent's grants is invisible and unaddressable to it.
- **`default_inbox`**: the granted inbox this agent sees as IMAP `INBOX` and the
  target of its send catch-all (below). It is **validated to be one of that
  agent's granted inboxes _with `read` access_** — a `send`-only default would be
  an un-`SELECT`able `INBOX`, so `read` on the default is required (its send
  catch-all additionally needs `send`, but a readable default with no send simply
  cannot be the catch-all target; see Send scoping). Equivalent surface form:
  `default: true` on exactly one grant. **When omitted:** if the agent has
  **exactly one** `read` grant, that inbox is inferred as the default; with **two
  or more** read grants and no `default_inbox`, the config is **rejected** (the
  agent's `INBOX` and send catch-all would be ambiguous). So every agent resolves
  to exactly one default, given or inferred.

### Authentication is identity resolution

Today a single credential is compared constant-time at IMAP `LOGIN`
(`imap.go`) and SMTP `AUTH` (`smtp.go`). This generalizes to a **map of agents**:
the presented username selects the agent record, and its password is compared
**constant-time** (`subtle.ConstantTimeCompare`, unchanged primitive). A miss on
either username or password fails auth identically — no username-enumeration
oracle. On success the resolved **agent and its grants become the session
principal**, carried for the life of the connection and consulted on every
subsequent operation.

### Read scoping (IMAP)

The connected agent's grants gate the inbound face:

- **`LIST`** returns only the inboxes the agent holds `read` on (plus its
  `default_inbox` as `INBOX`). Ungranted inboxes are not listed.
- **`SELECT` / `STATUS`** on an inbox the agent lacks `read` on returns
  **no-such-mailbox** — identical to a name that does not exist, so absence is
  indistinguishable from non-existence (privacy by omission).
- Fetch / keyword-write inherit the selected mailbox's grant; an agent can never
  reach an inbox it did not `SELECT`, and it cannot `SELECT` an ungranted one.

### Send scoping (SMTP)

ADR 0023 routes an outbound submission by matching its **From** to a configured
inbox `identity`. Multi-agent adds an authorization gate **before** the message
is enqueued: if the resolved inbox is one the connecting agent lacks `send` on,
the submission is **rejected at submit** (fail-closed, ADR 0003) — it is never
trapped in the sluice. A read-only grant therefore cannot originate mail even for
an inbox the agent can see. Rejection is at `MAIL FROM`/`DATA`, the same fail-
closed seam ADR 0023 uses for an unroutable From.

This gate depends on the submission being **authenticated**, which it already is:
the SMTP face requires `AUTH` today (an unauthenticated `MAIL FROM`/`DATA` is
rejected with auth-required), and there is no localhost/unauthenticated submit
path. Whenever `agents:` is set, the authenticated username **resolves to the
agent principal** and is therefore known at `MAIL FROM`, which is exactly what
makes per-agent send-scoping possible; an unauthenticated submit is rejected
before any From is considered, unchanged from today. So enabling `agents:` does
not open a new unauthenticated path — it only refines who an already-required
authentication resolves to.

### Principal / mail-owner decoupling (the one real refactor)

Today the login username doubles as the store **owner key**: the IMAP session
sets `s.owner = username` and the per-inbox sync writes records under that same
username (`imapsync.New(..., cli.AgentUsername, ...)`). The two are equal today
**only because there is one agent** — a coincidence, not a design.

With several agents on one inbox, the owner key **cannot** be the connecting
login, or two agents sharing an inbox would key into two disjoint record sets and
never see the same mail. So the store owner key becomes a **stable per-inbox
mail-owner**, a property of the inbox rather than of whoever connects. The sync
writes under the inbox's mail-owner; a read session resolves records by
`(inbox-mail-owner, inbox)` and uses the **connecting agent only to gate access**,
not to key storage. This cleanly separates *who is asking* (the agent principal)
from *whose mail it is* (the inbox mail-owner). The `(owner, inbox)` composite key
of ADR 0016 is unchanged in shape; only the source of the `owner` value moves off
the login.

The mail-owner value is **fixed to the inbox `name`** (already unique per ADR
0023), rather than adding a config field. For backward compatibility the implicit
single-agent path (below) keeps the existing owner value, so **no stored record is
rekeyed** on that upgrade. A deployment that *introduces* `agents:` over an
existing multi-inbox store is the one case that touches stored data; see
**Migration** below.

### Bounce scoping (a second, per-agent key-space)

The owner-decoupling above governs **synced upstream mail** only. Darbaan also
stores its **own generated bounces** (ADR 0006/0007) in the same inbound store, and
those must **not** fold into the inbox's shared mail-owner key: a bounce belongs to
the **agent whose submission failed**, and a read-only co-agent on a shared inbox
must never see it — that would leak one agent's send failures to another. Today a
bounce is keyed `Owner = orig.Agent` (the originating agent); **this ADR keeps
that**.

So the read face resolves **two distinct owner key-spaces** per connected agent and
selected inbox, and unions them:

- **(a) synced upstream mail** — records with an upstream coordinate
  (`UpstreamUID != 0`, ADR 0019), keyed by the **inbox-mail-owner** and **grant-
  gated** by the agent's `read`. Shared: co-readers of an inbox see the same mail.
- **(b) the connecting agent's own bounces** — locally-generated records
  (`UpstreamUID == 0`), keyed by the **originating agent id**. Private: only the
  agent that sent the failed submission sees its bounce — never a co-reader of the
  same inbox, never global.

The two spaces stay separate precisely because a bounce's owner is the **agent id**
while synced mail's owner is the **inbox name** — different owner values that never
collide, so the owner rekey must touch **only** synced records and leave bounces
alone (see Migration). This separation is load-bearing for the shared-inbox privacy
guarantee and is fixed here before slice 2 builds the decoupling.

### Per-agent default inbox → IMAP `INBOX`

Mailbox naming becomes **per-principal**. Today `mailboxName`/`resolveMailbox`
map the one global default inbox to `INBOX`; instead they key off the **connected
agent's** `default_inbox`: agent-a's `default_inbox` shows as `INBOX` to agent-a,
agent-b's (different) `default_inbox` shows as `INBOX` to agent-b, and each
agent's other granted inboxes appear under their own names. The send **catch-all**
likewise becomes per-agent: a submission whose From matches no configured inbox
identity routes to the **connecting agent's** `default_inbox` (extending ADR
0023's single catch-all, now scoped per agent), still subject to that agent
holding `send` on it. This keeps "reply from my default account" working
independently for each principal without a shared global default.

### Backward compatibility

A config with **no `agents:` list** behaves exactly as today: a **single implicit
agent** authenticated by the existing `DARBAAN_AGENT_PASS`, granted `read`+`send`
on **all** configured inboxes, whose `default_inbox` is the existing default inbox
(the ADR 0023 implicit `default` when there is also no `inboxes:` list). Its
mail-owner value is the current one, so existing stores keep resolving unchanged.
`agents:` is **opt-in**, exactly as `inboxes:` was in ADR 0023 — adding it is what
turns multi-agent on.

### Migration (owner-key rekey)

This is the **only** change in ADR 0027 that touches existing stored data, so it
is called out here rather than left implicit:

- **Single-agent → still single-agent (no `agents:`):** nothing changes. The
  implicit agent keeps the current owner value; no record is rekeyed.
- **Existing multi-inbox store → introducing `agents:`:** the mail-owner key moves
  from the old login username to the inbox `name`. Records synced before the
  upgrade carry `rec.Owner == <old-login-username>`; after the upgrade the read
  path resolves by `(<inbox-name>, inbox)` and would not find them until they
  re-sync. Slice 2 therefore ships a **one-time rekey**: a startup/admin step that
  rewrites `rec.Owner` from the old username to the owning inbox's `name` for every
  **synced** record (`UpstreamUID != 0`) **only** — locally-generated bounce
  records (`UpstreamUID == 0`) are **left keyed to their originating agent** per
  Bounce scoping, never rekeyed to the inbox. The rekey is idempotent and gated on
  a config marker so it runs once; it is a pure key rewrite — no content is
  touched. Slice 2's PR documents the exact invocation; until it runs, an upgraded
  deployment is expected to re-sync rather than lose mail (inbound sync is store-
  canonical and re-derivable, ADR 0019).

Fresh deployments and the single-agent path never hit this.

### Audit

ADR 0011's audit `Record` already carries the acting **agent id**, written on
enqueue / send-attempt / verdict — and once authentication resolves the login to
an agent (above), that id is the authenticated principal, so "which agent acted"
is already recorded. This ADR adds the **inbox id** alongside it, so every row
records *which agent acted, as which inbox* — the full tuple for a multi-agent
deployment. The implicit agent's id is the configured agent username (the value
SMTP already stamps as the submission `Agent`), so rows stay consistent across the
upgrade rather than switching to a synthetic sentinel.

## Boundaries / non-goals

- **No roles / RBAC.** Grants are a flat `(agent, inbox, {read,send})` list, not
  roles, groups, or inheritance. The permission surface is deliberately the two
  directions and nothing more.
- **No per-message ACLs.** Authorization is per-inbox-per-direction; there is no
  per-message or per-thread sharing.
- **The bounce-signing key stays global** (ADR 0023 boundary, unchanged) — it is
  a Darbaan-internal trust anchor, not a per-agent or per-inbox secret.
- **The operator approval gate stays global.** The Telegram approval pipeline
  (ADR 0004/0023/0025) is the operator's single control surface across all agents
  and inboxes; multi-agent does not split it per principal. Whose submission is
  being approved is visible via the audit acting-agent id, but there is one gate.
- **No cross-agent visibility of the roster.** An agent is not told which other
  agents exist or share its inboxes; it only ever sees its own grants.

## Consequences

- One Darbaan hosts several agent principals with least-privilege, per-direction
  access; a compromised agent reaches only its granted inboxes, only in its
  granted directions, and cannot enumerate what it lacks (omission = non-
  existence).
- Sharing is configuration-only: list an inbox under two agents. No new sharing
  primitive, no per-message plumbing.
- **Shared IMAP state is a consequence of sharing.** Two agents granted the same
  inbox key into the same `(mail-owner, inbox)` store, so per-message IMAP flag
  and keyword state (`\Seen`, `\Answered`, labels) is **shared** between them —
  one agent marking a message read shows it read to the other. This is the
  intended semantics for a genuinely shared inbox (one mailbox, one truth), but it
  is called out so it is not a surprise; agents wanting independent read-state
  should be granted **separate** inboxes, not a shared one.
- The principal/mail-owner split is the one structural change. Adding or removing
  agents is then pure config. The single-agent path and fresh deployments migrate
  with **no** data change; the sole data-touching case is an existing multi-inbox
  store adopting `agents:`, which runs the one-time owner rekey (see Migration).
- **A bounce is private to its originator.** Synced mail on a shared inbox is
  shared, but Darbaan-generated bounces stay keyed to the agent that sent the
  failed submission, so a read-only co-agent never learns another agent's send
  failures — the two key-spaces guarantee it.
- The audit log answers "which agent did this" for every action, closing the last
  gap ADR 0010/0023 left open.

## Resolved in review

Both originally-open decisions were endorsed by both reviewers and are folded into
the Decision above:

- **Mail-owner value:** the inbox `name` (unique per ADR 0023), no new config
  field; migration handled by the one-time rekey (see Migration). Still subject to
  the operator's veto — an explicit per-inbox `owner` field could be added if a
  value other than the inbox name is ever wanted.
- **`default_inbox` vs `default: true`:** `default_inbox` is the primary spelling,
  `default: true` on one grant is sugar; exactly one default per agent, given or
  inferred (see Config shape), required to have `read`.

## Follow-ups

- Optional per-agent view of a unified read-only "all my inboxes" mailbox (the
  ADR 0023 follow-up, now naturally per-principal).
- An approver that is itself an agent principal (ADR 0010's sketch) — the acting-
  agent audit id is the hook.

## Slices

Implemented as four PRs, each independently reviewable:

1. **Config schema + per-agent auth + backward-compat implicit agent** — the
   `agents:`/`grants:`/`default_inbox` schema and validation, the per-agent
   password env map, the username→agent constant-time resolution, and the
   implicit single-agent fallback (all-inboxes read+send) when `agents:` is
   absent. No scoping behavior yet beyond auth.
2. **IMAP read-scoping + principal/mail-owner decoupling + per-agent `INBOX`** —
   grant-gated `LIST`/`SELECT`/`STATUS`, the owner-key decoupling, per-principal
   mailbox naming (`default_inbox` → `INBOX`, per-agent send catch-all), the
   two-key-space read union (inbox-mail-owner synced mail + originating-agent
   bounces, kept separate), and the synced-only owner rekey (bounces untouched).
3. **SMTP send-scoping** — reject-at-submit when the connecting agent lacks
   `send` on the resolved inbox.
4. **Audit acting-agent id + docs + this ADR** — thread the agent id through the
   audit rows, document the config, and finalize this record (status → Accepted,
   README table, any amendment reconciling the shipped shape).

Relates to ADR 0002, 0003, 0004, 0009, 0010, 0011, 0012, 0016, 0019, 0021, 0022,
0023, 0025.
