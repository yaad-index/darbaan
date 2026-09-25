# ADR 0034: Sending without approval when every recipient is an operator identity

**Status:** Proposed (2026-09-25, pending operator sign-off)

## Context

Every outbound message is held for approval (ADR 0003). For mail the operator sends
to themselves — a receipt, a report, a copy of something for their own records — that
hold buys nothing: the approval step and the delivery both end with the same person
reading the same bytes. The round-trip adds latency and an interaction, and the
interaction has no decision in it.

ADR 0003 already provides for this. Its decision names "approval chains, allowlists,
any future auto-approve" as send-permitting paths, and requires only that each one be
**human-configured**: *"Only the human's configuration can loosen sending, never the
agent or an injection."* So this ADR does not supersede or narrow 0003; it defines one
specific path that 0003 anticipated, and inherits 0003's constraint on how such a path
may be configured.

## Decision

A message sends without the approval hold when **every recipient is an operator
identity** — an address the operator themselves reads, listed in host configuration.

1. **Match on the address only**, ignoring the display name: `Some Name <a@b.tld>` and
   a bare `a@b.tld` both match the entry `a@b.tld`. Exact on the address — no domain
   matching, no wildcards, no substring.
2. **Every recipient must match**, across `To`, `CC` and `BCC` alike. A single
   non-matching address sends the **whole message** through the normal approval
   routine. There is no partial send and no splitting of a message by recipient.
3. **Configuration only.** The identity list lives in host config. It is not writable
   through the admin API and not settable by a submitting client. This is 0003's
   requirement restated, and it is the whole safety argument: a gate whose exemptions
   the submitter can widen is self-serve rather than default-deny.
4. **Absent or empty list means today's behaviour** — everything is held. The path is
   opt-in and off by default, so no existing deployment changes disposition on upgrade.

## Why this recipient class and no other

For a message whose recipients are all operator identities, **approving it is the
operator reading it and delivering it is the operator reading it.** The bypass has the
same audience as the gate, so it cannot place content in front of anyone who would not
otherwise have seen it, and no third party can be reached at all.

That reasoning does not extend to an arbitrary recipient, however routine the
correspondence. There, skipping approval means content reaches someone who is not the
approver, and the approval step was the only thing between a wrong or manipulated
message and that person. The distinguishing question is not how repetitive the mail is
but **who ends up reading it**.

Two consequences of that framing, stated because they are the parts that would decay
first: a recipient who *acts* on what they receive — a bank, an employer, a service
provider, a support desk — must never be configured here, and the recipients that
generate the most repetitive mail are disproportionately in that group, which is where
pressure to widen this will come from.

## Fail-safe

0003's fail-closed property is preserved exactly. An unapproved message still waits
forever; nothing decays from "held" into "sent". The new path is not a timeout or a
deferred release — a message either matches the configured identities at submission and
sends, or it is held under the existing rules. There is no state in which a held
message later becomes eligible without a human acting.

## Audit

A bypassed send is recorded in the audit log and **marked as bypassed**. Without the
marker the fastest path through the system would be the one that leaves no trace, and
"no entry in the log" would stop meaning "nothing was sent". This matters more here
than on the held path, because `Enqueue` records no actor, so an unmarked bypass would
be close to invisible after the fact.

## Consequences

- Self-directed mail stops requiring an interaction whose only output is the operator
  seeing bytes they were about to be shown anyway.
- **A bypassed message arrives on a surface where the operator is reading rather than
  judging.** A wrong or manipulated message therefore looks ordinary instead of
  arriving flagged for a decision. Accepted for this recipient class specifically,
  because the alternative is an approval step with no decision in it.
- The injection-assessment score is **not** a compensating control on this path. It
  decides what is flagged, not what is sent, and it has no ground truth, a threshold
  that is asserted rather than measured, and output that cannot currently be checked
  independently. It was never load-bearing while everything was held; it is not
  load-bearing here either.

## Boundaries

- Does not extend to non-operator recipients. Widening it is a separate decision with a
  separate argument.
- Does not change what is held, only whether a matching message is held at all.
- Does not introduce a per-sender or per-agent exception: the condition is a property of
  the **recipients**, never of who submitted the message.
