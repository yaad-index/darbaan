# ADR 0022: Per-inbox default visibility (filter mode) — match-only rules over a default disposition

**Status:** Proposed (2026-06-29)

## Context

ADR 0008 + ADR 0021 built the inbound filter as a **serve-time view** over the
store-canonical records: an ordered rule list, **top-down first-match-wins**, each
rule carrying one explicit **action** (`allow` / `hide` / `hold-for-human`), and a
**configurable default action** on no match (default `allow`). The engine
(`internal/filter`) already supports all of this, including a `label` match field
(ADR 0020).

Operationally an inbox has one of two natural *dispositions*, and the operator
should declare it once rather than repeat an `action:` on every rule:

- A **noisy personal inbox** (e.g. a busy personal Gmail): the agent should
  see **nothing by default**, and rules name the few things worth surfacing
  (e.g. "only mail labeled `x`"). Default-deny; rules are an **allowlist**.
- An **assistant inbox** (`forudassistant`): the agent should see **everything by
  default**, and rules name the noise to suppress (e.g. "hide mail from
  `a@b.com`"). Default-allow; rules are a **denylist**.

Today both are *expressible* (set `default: hide` + `action: allow` rules, or
`default: allow` + `action: hide` rules), but the operator must hand-write the
default and stamp an action on every rule, and the relationship between "what the
inbox does by default" and "what a rule means" is implicit. This ADR makes that
disposition a **first-class per-inbox setting** and lets rules be **match-only**,
with the mode deciding what a match does. It **refines ADR 0008/0021; it does not
change the evaluation engine's semantics.**

## Decision

Introduce a per-inbox **default visibility** setting that fixes both the no-match
default and the meaning of a bare (action-less) rule.

### The setting

```yaml
default_visibility: visible | hidden    # single canonical key, no alias
```

`visible` is the default when the key is **absent**, so every existing ADR 0021
config keeps working unchanged.

**One key, no alias.** `whitelist`/`blacklist` are kept only as the *conceptual*
framing in this prose (whitelist = visible / default-allow; blacklist = hidden /
default-deny); they are **not** config surface. A `mode: whitelist|blacklist` alias
was considered and rejected: it adds parsing complexity, and "a *blacklisted* inbox
*shows* on match" is exactly the inversion that misleads a future reader.
`visible|hidden` says what it does.

### Semantics

```
default_visibility: visible  (whitelist) — no match -> SHOW ; bare-rule match -> HIDE
default_visibility: hidden   (blacklist) — no match -> HIDE ; bare-rule match -> SHOW
```

A **bare rule** (no `action:`) takes the **inverse of the default disposition** — a
match flips visibility. The filter syntax (match fields, operators) is **identical
in both modes**; only the inbox-level disposition changes what a match means and
what the default is. The two dispositions map directly to the
two motivating inboxes: *one blacklisted showing only label `x`; another
whitelisted hiding only `a@b.com`* (see Examples).

### `hold-for-human` stays explicit

The third action does not have an inverse, so it is **never implied** by the mode.
A rule may still carry an **explicit** `action:` in either mode — including
`hold-for-human` to route a match to the approval surface (ADR 0021), or an
explicit `allow`/`hide` that reads more clearly than relying on the flip. Explicit
action always wins over the mode-implied one. So:

- bare rule → mode-implied flip (`hide` under `visible`, `allow` under `hidden`);
- `action: hold-for-human` → held for approval, in either mode;
- `action: allow|hide` → that action verbatim (the ADR 0021 behavior).

### Engine impact (minimal)

`Filter.Decide` (first-match action, else default) is **unchanged**. The change is
at **compile/load** (`internal/filter/load.go`):

1. Parse `default_visibility` → set `Filter.def` to `Allow` (visible) or `Hide`
   (hidden). Reject specifying both `default_visibility` and the legacy `default:`
   with conflicting values; if only legacy `default:` is present, honor it
   (back-compat).
2. Allow `ruleConfig.Action` to be **empty**; when empty, fill it with the inverse
   of the resolved default (`visible`→`Hide`, `hidden`→`Allow`). A non-empty action
   is parsed and used as today.

No change to match evaluation, the store, or the read face.

## Examples

**Inbox 1 — personal, blacklist (default-deny), surface only label `x`:**

```yaml
default_visibility: hidden        # default-deny (the "blacklist" disposition)
rules:
  - match:
      - {field: label, op: equals, value: x}
    # no action -> SHOW (the flip): only label-x mail reaches the agent
```

**Inbox 2 — assistant, whitelist (default-allow), hide one sender:**

```yaml
default_visibility: visible       # default-allow (the "whitelist" disposition; also the implicit default)
rules:
  - match:
      - {field: from, op: equals, value: a@b.com}
    # no action -> HIDE (the flip): everything reaches the agent except a@b.com
```

## Boundaries / non-goals (this increment)

- **Single-inbox config surface.** This ADR adds the disposition to the *current*
  single inbound filter. Making `{default_visibility + rules}` a **per-inbox** unit
  for **N inboxes in one Darbaan** is ADR 0023 (multi-inbox), which realizes ADR
  0010; this ADR is its prerequisite.
- **No new match capability.** Label matching already exists (ADR 0020/0021); the
  blacklist-by-label example relies on it and needs nothing new. Body/text matching
  and redaction remain deferred (ADR 0008/0021).
- **Not containment.** Inbound visibility is privacy/noise control, not injection
  defense — the outbound trap (ADR 0003) remains the containment boundary.

## Consequences

- The common case becomes a one-liner: declare the inbox's disposition, write
  match-only rules. The default→rule relationship is now explicit and auditable.
- Fully backward compatible: absent key ⇒ `visible`; legacy `default:` + explicit
  per-rule actions keep working untouched. ADR 0021 configs need no edits.
- `hold-for-human` composing with both modes preserves the inbound approval queue
  symmetry (ADR 0021) regardless of disposition.
- Sets up multi-inbox (ADR 0023): the per-inbox unit is now `{default_visibility,
  rules}`, ready to be instantiated per mailbox.

## Follow-ups

- ADR 0023 multi-inbox: scope `{default_visibility, rules}` per inbox + per-inbox
  backend; collapse the two current single-mailbox deployments into one.
- Config validation message quality: a bare rule under each mode should be
  explainable in `--explain`/dry-run output (which action it resolved to and why).

Relates to ADR 0003, 0008, 0010, 0020, 0021.
