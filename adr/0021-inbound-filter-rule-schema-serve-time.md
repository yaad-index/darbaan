# ADR 0021: Inbound filter — rule schema, operators, and serve-time evaluation

**Status:** Accepted (operator sign-off recorded by approval of the PR that sets this status; proposed 2026-06-27); amended 2026-09-26 (see the end)

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
  (a synced or agent keyword, ADR 0020), `age` (message age, e.g. `> 30d`). In v1
  `header` matches **envelope headers only** (from/to/cc/subject/date/message-id/
  reply-to — the stored set); matching an arbitrary non-envelope header would force
  a content fetch, so it's deferred with body-match.
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

### Evaluation point + state

Rules are evaluated **fresh each serve** against the current ruleset — the
rule-derived states (`allow`/`hide`) are **not cached**, so an edited ruleset
takes effect immediately and there is no stale-cache-on-rule-change problem
(evaluation is cheap: metadata-only, no body fetch). Only the **human
`hold-for-human` decision** (approve/reject) is **persisted** on the record,
because it is a human action not re-derivable from rules — a held message stays
held across restarts and is never re-asked. Filtering needs only **metadata**
(from/to/subject/envelope-header/label/age — all stored eagerly, ADR 0019/0020),
so it never forces a body fetch.

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
  surface, which gains a **second queue**: the operator sees two decision types
  (outbound "send this?" and inbound "expose this?"), tagged by direction.
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

## Amendment (2026-09-26): inbound order, and one meaning of "reject"

Decision on item A7 of #237; text above stays as written (ADR 0037). Recorded in ADRs
0021 and 0032, and applies with ADRs 0024 and 0030.

**Order.** Spoof-guard, then **assessment at ingest, for every message**, then filter
rules **at serve time**. Filter rules are evaluated when mail is read and can be edited
at any time, so skipping assessment for mail a rule currently hides would let that mail
become visible unassessed the moment the rule changes, which ADR 0032's core invariant
forbids. The cost of assessing mail a rule hides is accepted.

**Reject.** Rejecting a held message means one thing, whatever held it: **a
tombstone.** The message's content is never served to the agent again; the agent sees
that a message was received and reviewed out, with no attacker bytes; the metadata and
the audit record of the verdict are kept. **The upstream mailbox copy is not touched**:
upstream is read-only for message content (ADR 0019, as narrowed by ADR 0020).

Today the read face tombstones a rejected assessment hold but simply hides a rejected
filter hold. The unified tombstone follows this amendment in code.


## Amendment (2026-09-26): a human hold decision outranks later rule results

Decision on item A15 of #237; text above stays as written (ADR 0037).

Rules are re-evaluated whenever mail is read, so a rule edit can change the result for
a message a human has already decided. **For that message, the human decision wins**:
once a message has a hold decision, that decision determines whether it is served,
whatever the rules say later. An approved message stays served if a new rule would
hide it; a rejected message stays a tombstone (see the order and reject amendment) if
a new rule would allow it. Rules keep re-evaluating as today for every message without
a decision; there is no arrival-time cut-off.

Today a later rule result overrides the decision in both directions. Decision-wins
follows this amendment in code.
