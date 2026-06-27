# ADR 0021: Inbound filter — rule schema, operators, and serve-time evaluation

**Status:** Proposed (2026-06-27)

## Context

ADR 0008 locked the inbound filter's shape: declarative YAML rules matched on
message fields, evaluated **top-down, first-match-wins**, with v1 actions
**hide / allow / hold-for-human** and a configurable **default-allow** on no
match. Since then the inbound half was built concretely — store-canonical
incremental sync (ADR 0019), lazy content, a recency cutoff (the sync-level
recency dimension of ADR 0008, shipped), and agent labeling (ADR 0020).

This ADR makes the filter **buildable**: the rule/match schema, the evaluation
point in the now-existing pipeline, how each action is realized over the store,
and what's deferred. It **refines ADR 0008; it does not change its decisions.**

## Decision

**The filter is a serve-time view over the store-canonical synced records.** The
store keeps every synced message; rules are evaluated per message when the IMAP
read face lists/serves it, and the filter decides what the agent sees.

### Rule schema (YAML)

A filter is an ordered list of rules; each rule is **match conditions + one
action**. Top-down, **first match wins** (ADR 0008); no match → the configured
**default action** (default `allow`, ADR 0008 amendment).

- **Match fields:** `from`, `to`/`cc`, `subject`, `header` (name + value), `label`
  (a synced or agent keyword, ADR 0020), `age` (message age, e.g. `> 30d`).
- **Operators:** `equals`, `contains`, `regex`, plus `domain` for addresses
  (match the address domain). A rule's conditions are **AND**ed; `or` is expressed
  as separate rules (first-match-wins covers it).
- **Action:** `allow` | `hide` | `hold-for-human`.

### How each action is realized (over the store-canonical records)

- **allow** — served normally by the read face.
- **hide** — the record stays in the store but is **omitted from the read face**
  (not listed, not fetchable). Because Darbaan owns its UID namespace
  (store-canonical, ADR 0016), omitting a record is just a filtered view — none of
  the live-upstream UID/sequence hazard that made hiding-from-a-live-proxy unsafe
  (ADR 0001).
- **hold-for-human** — the record is held (hidden from the agent) and routed to
  the **approval surface** (the localhost admin API + Telegram client,
  ADR 0004/0017), mirroring the outbound sluice: the human is asked "expose this
  to the agent?". On **approve** → the record becomes `allow` (visible); on
  **reject** → `hide`. The held/decided state is **persisted** on the record (like
  the sluice's pending state), so a restart doesn't re-ask and the decision is
  stable.

### Evaluation point + caching

Rules are evaluated when the read face first needs a message's filter-state (at
LIST / first serve), and the **resolved state is cached on the record** so
re-listing is cheap and a `hold-for-human` decision stays put. Filtering needs
only **metadata** (from/to/subject/header/label/age — all stored eagerly,
ADR 0019/0020), so it never forces a body fetch.

### Configuration

The rule list is YAML, loaded at `serve` start (file `<` env `<` flag layering).
The default action is **always explicit** in config (ADR 0008). Hot-reload is
deferred.

## Boundaries / non-goals (this increment)

- **No CEL.** Structured fields + operators cover v1; a future optional `cel:`
  condition is the escape hatch if expressiveness falls short — one matcher kind
  alongside the structured ones, capability-gated like the other pluggables. Not
  now.
- **No redaction** (altering contents) — deferred post-v1 (ADR 0008), which also
  defers **body/text matching**: v1 matches metadata only (from/to/subject/header/
  label/age), never the body.
- **Not containment.** Inbound filtering is privacy / noise / attack-surface
  control; it does **not** stop a prompt injection from an allowed sender — the
  outbound trap (ADR 0003) is the real containment (ADR 0008).

## Consequences

- The rule engine stays small + auditable (structured matchers, first-match) and
  runs as a **view over the canonical store** — no UID hazard, re-evaluable,
  decisions persisted.
- `hold-for-human` completes the symmetry: outbound traps **sends** for approval;
  inbound holds **reads** for approval — both over the same admin-API / Telegram
  surface.
- Labels (ADR 0020) are first-class match input, so agent/rule labeling and
  filtering compose (e.g. hide anything the agent labeled `useless`).
- The recency cutoff (shipped) is the cheap pre-filter; the rule engine handles the
  per-message policy on what remains.

## Follow-ups

- CEL escape-hatch condition (capability-gated), if structured operators prove
  insufficient.
- Body/text matching + redaction (post-v1, ADR 0008).
- Hot-reload of rules.

Relates to ADR 0001, 0003, 0004, 0008, 0016, 0017, 0019, 0020.
