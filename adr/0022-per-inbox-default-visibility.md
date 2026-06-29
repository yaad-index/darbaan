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

**One key, no alias.** The plain-language reading of `visible`/`hidden` is
**default-allow** / **default-deny** — that is what the no-match default does. A
`mode: whitelist|blacklist` alias was **considered and rejected**: it adds parsing
complexity and is consistently backwards from common meaning — under a "blacklist"
inbox a *matching* rule gets **shown** (opposite of "blacklisted items are
blocked"), and under "whitelist" a match gets **hidden**. `visible|hidden` already
names the exact thing being configured, so no alias is carried. (Historical note
only: the disposition was discussed in whitelist/blacklist terms; if an alias is
ever wanted for familiarity, `mode: default-allow|default-deny` is the unambiguous
spelling — never `whitelist|blacklist`.)

### Semantics

```
default_visibility: visible  (default-allow) — no match -> SHOW ; bare-rule match -> HIDE
default_visibility: hidden   (default-deny)  — no match -> HIDE ; bare-rule match -> SHOW
```

A **bare rule** (no `action:`) takes the **inverse of the default disposition** — a
match flips visibility. The filter syntax (match fields, operators) is **identical
in both modes**; only the inbox-level disposition changes what a match means and
what the default is. The two dispositions map directly to the two motivating
inboxes: *one default-deny showing only label `x`; another default-allow hiding
only `a@b.com`* (see Examples).

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
   (hidden).
2. Allow `ruleConfig.Action` to be **empty**; when empty, fill it with the inverse
   of the resolved default (`visible`→`Hide`, `hidden`→`Allow`). A non-empty action
   is parsed and used as today.

**Legacy `default:` coexistence (back-compat, precise).** `default_visibility` and
the legacy `default:` action (ADR 0008/0021) name the same no-match default, so:
- only **legacy `default:`** present → honor it (existing configs unchanged);
- **both present and agreeing** (`default: allow` + `default_visibility: visible`,
  or `default: hide` + `... hidden`) → **accepted** (synonyms; not an error);
- **both present and contradicting** (`default: allow` + `default_visibility:
  hidden`, etc.) → **rejected** at load, fail-fast. Only a genuine contradiction is
  an error — agreement is fine.

No change to match evaluation, the store, or the read face.

### Resolved-rule visibility (`filter explain`) — in scope

A bare rule is opaque to a reader who doesn't know the inbox disposition, so the
safety net ships **with** this change, not as a follow-up: at load time each rule
records its **resolved** action and whether that action was **explicit** or
**implied** by `default_visibility`, and a `filter explain` dry-run prints the
default disposition plus a per-rule table (`#`, match, resolved action, source).
This makes the bare-rule flip auditable without starting `serve` or reading mail.

## Examples

**Inbox 1 — personal, default-deny, surface only label `x`:**

```yaml
default_visibility: hidden        # default-deny
rules:
  - match:
      - {field: label, op: equals, value: x}
    # no action -> SHOW (the flip): only label-x mail reaches the agent
```

**Inbox 2 — assistant, default-allow, hide one sender:**

```yaml
default_visibility: visible       # default-allow (also the implicit default)
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
  default-deny-by-label example relies on it and needs nothing new. Body/text
  matching and redaction remain deferred (ADR 0008/0021).
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

Relates to ADR 0003, 0008, 0010, 0020, 0021.
