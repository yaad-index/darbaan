# ADR 0023: Multi-inbox — N inboxes in one Darbaan, each with its own backend, filters, visibility, and identity

**Status:** Proposed (2026-06-29)

## Context

ADR 0010 decided **multi-mailbox + single-agent** for v1 ("Darbaan fronts N
upstream accounts, each with its own credentials, filter rules, and approval
policy") but left it a sketch — the single-inbox path is what actually shipped, so
two real deployments (an assistant mailbox and a personal mailbox) run today as
**two separate Darbaan instances**. ADR 0022 made `{default_visibility, rules}` the
per-inbox policy unit and explicitly named this ADR as the step that scopes that
unit per inbox. This ADR makes multi-inbox concrete: the config shape, how the
single agent **addresses** each inbox in both directions, how per-inbox backends /
filters / identities compose, and how the existing single-inbox config migrates. It
**realizes ADR 0010; it keeps single-agent** (multi-*agent* tenancy stays deferred
per 0010).

## Decision

**An "inbox" becomes a first-class, named config entity, and Darbaan serves a list
of them over one agent-facing connection.** One agent principal (ADR 0010) sees all
inboxes; there is no per-agent permission matrix yet.

### Config shape

```yaml
inboxes:
  - name: work                      # stable id; also the IMAP mailbox name (below)
    backend: { ... }                # a pluggable backend (ADR 0009): upstream IMAP/SMTP or Gmail + creds
    identity: agent@company.example # the From/envelope identity Darbaan sends as for this inbox
    default_visibility: visible     # ADR 0022 unit ...
    rules: [ ... ]                  # ... per inbox
  - name: personal
    backend: { ... }                # e.g. the Gmail provider backend (ADR 0009)
    identity: me@personal.example
    default_visibility: hidden
    rules: [ - {match: [{field: label, op: equals, value: x}]} ]
```

Each inbox carries its **own** backend (ADR 0009 capability negotiation applies
per inbox — a Gmail-label rule runs on a Gmail-backed inbox, degrades on a generic
one), its **own** `{default_visibility, rules}` (ADR 0022), its **own** inbound sync
(ADR 0019), bounce-spoof guard (ADR 0024), and label namespace (ADR 0020). This
collapses the two current separate deployments into one Darbaan.

### Agent addressing — inbound: IMAP mailboxes, one per inbox

**Each inbox is exposed to the agent as a named IMAP mailbox** (folder); the agent
`SELECT`s `work` or `personal` to read that inbox. Chosen over per-inbox logins:
it is IMAP-native (the agent already speaks mailboxes), keeps **one** agent
credential (ADR 0010 single-agent; no credential multiplication), and Darbaan
remains the agent's sole IMAP source. Darbaan owns the UID namespace
store-canonically (ADR 0016) **per mailbox** — each inbox is an independent
UID/keyword space, so sync state and filtering stay isolated. The serve-time filter
view (ADR 0021/0022) is evaluated against the SELECTed inbox's ruleset.

### Agent addressing — outbound: identity selects the inbox

On SMTP submit, the message's **From** selects which inbox the mail is sent
**as/through**: it must match a configured inbox `identity`, and the mail routes out
via **that inbox's backend**. A reply defaults to the identity of the inbox that
**received** the original (Darbaan knows which mailbox a held/synced message belongs
to), so "reply" stays on the right account without the agent having to restate it.
A From that matches no configured identity is **rejected at submit** (fail-closed,
ADR 0003 spirit) rather than silently sent from a default — sending as the wrong
account is the failure mode to prevent.

### Sender override at the approval gate (Change)

The approval gate gains the operator control deferred from ADR 0025: the Telegram
decision message shows **Approve** + **Change**. **Change** lists the configured
inbox **identities**; tapping one **approves-and-sends from that identity**, routed
through that inbox's backend. The default selection is the From the agent set (or
the receiving inbox's identity for a reply). This is the multi-inbox realization of
operator sender control — the valid-senders list is exactly the configured inbox
identity set, nothing free-form.

### Migration / backward compatibility

A config with **no `inboxes:` list** is treated as a **single implicit inbox**
(`name: default`) built from the existing top-level backend + `default_visibility` +
`rules`. Existing single-inbox configs keep working unchanged; the agent sees one
mailbox (`INBOX`/`default`) exactly as today. `inboxes:` is **opt-in**; adding it is
what turns on multi-inbox.

## Boundaries / non-goals

- **Single-agent only (ADR 0010).** N inboxes, one agent principal seeing all of
  them. Multi-*agent* tenancy (per-agent logins, `(agent, inbox, direction)`
  permission matrix) stays deferred — this ADR must not foreclose it, so audit rows
  and per-inbox policy already carry an inbox id the matrix could later key on.
- **No cross-inbox mixing.** Each inbox is an isolated mailbox + UID space + ruleset;
  there is no unified/virtual "all inboxes" mailbox in v1 (possible follow-up).
- **No new filter/match capability.** Reuses ADR 0021/0022 wholesale per inbox.

## Consequences

- One Darbaan replaces the two current single-mailbox deployments; one agent
  connection, two (or N) mailboxes, each with independent policy and identity.
- Outbound can never silently leave as the wrong account: identity must match a
  configured inbox or it is rejected, and the gate's Change list is bounded to the
  configured identities.
- Per-inbox isolation (UID space, sync state, rules, labels, bounce-guard) means a
  noisy personal inbox and a curated assistant inbox coexist without bleed.
- The inbox id threaded through storage + audit leaves the multi-agent matrix (ADR
  0010) addable later without reshaping data.

## Open decisions (for review)

- **Addressing scheme:** this ADR decides **IMAP mailboxes per inbox** (vs separate
  per-inbox logins). Flagged for the operator's veto — separate logins would suit a
  future multi-agent split but cost credential multiplication now.
- **Mailbox naming:** flat (`work`, `personal`) vs nested under `INBOX/`. Leaning
  flat top-level mailboxes; minor, settle in implementation.
- **Unmatched-From on submit:** reject (chosen) vs route to a configured default
  inbox. Reject is safer; revisit if it proves annoying in practice.

## Follow-ups

- Approval-gate **Change** button implementation (Telegram), drawing the identity
  list from the configured inboxes (the ADR 0025 sibling, now unblocked).
- Optional unified read-only "all inboxes" virtual mailbox, if the agent wants one
  pane.
- Multi-agent tenancy (ADR 0010 deferred sketch), keyed on the inbox id this ADR
  introduces.

Relates to ADR 0002, 0003, 0009, 0010, 0016, 0019, 0020, 0021, 0022, 0024, 0025.
