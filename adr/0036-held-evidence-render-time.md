# ADR 0036: Show the matched evidence on a held message, at render time only

**Status:** Accepted (operator sign-off recorded by approval of the PR that added this ADR). Decides #263.

## Context

A message held by injection assessment (ADR 0032) reaches the operator as a card naming
the factor that fired, glossed into plain words, above the fenced stored body. Naming the
factor tells the operator **which rule fired**. It does not tell them **whether the rule
was right about this message**, and the only thing that does is the text that matched.

That distinction is the whole of the current false-positive problem. The known false
positives are legitimate mail that *discusses* what a rule looks for — a security code, a
"verify your account" line. By factor alone that class is indistinguishable from a true
positive, so no amount of glossing resolves it. The operator's approval is the control in
this system; without the matched span that approval is a judgement made on the category of
a message rather than on its content.

The obstacle is a documented boundary. `inbound.Assessment` (`internal/inbound/inbound.go`)
states that every field is system-defined and carries no message bytes, and that the
scorer's reason string is deliberately excluded from the stored record. Attacker-controlled
text in a stored, replayed, audited record is a wider surface than the same text rendered
once into a fenced operator notification.

Two facts from the current code shape the choice:

- **The hold card already fetches the stored body at render time.** `notifyHold`
  (`internal/telegram/holds.go`) calls `HeldContent` and fences the result (ADR 0032
  change A). A render-time match therefore adds no new fetch. ⚠️ **For body-scoped
  factors the quoted bytes are already on the card. That is NOT true for every factor:**
  `fencedBody` renders the decoded body only, while the attachment-directive factor matches
  attachment text and the secrets-request factor matches across body and attachments. A
  span from those factors quotes text the card does not otherwise show. The audience is the
  same operator and the text is fenced, so this is accepted, but it is a new exposure to the
  operator chat and is not covered by the "already on the card" argument. Each span
  therefore names its source (the body, or the attachment's filename).
- **The detector only answers yes or no.** `matchesAny` (`internal/assessor/heuristic.go`)
  uses `MatchString`. Returning a span needs a new method; it is not a flag to flip.

## Decision

**Option A: re-run the match when the card is built, quote the span fenced, and discard
it.** The stored record is unchanged, so the `inbound.Assessment` invariant holds exactly as
written and does not need restating.

Options not taken, and why:

- **B, store the span with the assessment.** Consistent with the verdict by construction,
  but it puts attacker text into a stored, replayed, audited record — the precise thing the
  invariant exists to prevent.
- **C, store a redacted descriptor (rule id plus offsets, or a normalised shape).** Keeps
  bytes out, but an operator cannot judge a true positive from offsets, so it keeps the
  safety and discards the point.

### Where the match runs

The span is computed on the daemon side, by **the ingest path's detector instance** with
its *current* configuration, which can differ from the configuration that produced the
stored verdict (that difference is exactly the disagreement case below). It is handed to the
notifier as transient data alongside the content it already fetches. **The notifier must not construct its own detector.** Two
detectors built from two copies of the configuration can disagree silently, which is the
failure the next section exists to handle rather than to multiply.

The evidence route returns message bytes and requires **`holds:read`** (ADR 0029), the
scope `HeldContent` already requires, and nothing broader.

⚠️ **This needs new wiring, not just a new method.** `admin.Service` holds no reference to a
detector or assessor today: `NewService` takes none, and no field carries one. The detector
has to be injected the way the service's other late-bound dependencies already are (the
sender, guard and filter setters), and it must be the instance the ingest path scores with,
not a second one constructed for the admin side.

### Required behaviour when the re-run disagrees

The render-time match is a **second observation**, and it can disagree with the stored
verdict: ADR 0035 makes the pattern set operator-configurable, so the ruleset can change
between assessment and render, and the stored content can be re-fetched. When a stored
factor has no span in the re-run, **the card names the factor, quotes nothing, and says so
explicitly**. The card may say only what the system actually observed: *"matched text not
available: the current rules no longer match this message"*.

⚠️ **The card must not state WHY.** A rule change, a re-fetch that returned different content,
and a defect in the re-run all produce the same observation, and the stored record cannot
tell them apart. Attributing the disagreement to a rule change needs the per-message record
of which factors were ACTIVE, which ADR 0035's consequences require and which is not yet
implemented. And even that field would show only a factor switched *off*, not patterns
*edited*. Backing "the rules changed" would need a digest of the effective pattern set recorded
with each assessment. Until something records that, the fallback states the observation and
never a cause.

🚨 **Quoting a span for a factor that is no longer the reason is worse than quoting none.**
It presents stale evidence as current with no signal that it is stale, to an operator whose
entire task at that moment is to judge the evidence.

⚠️ **And absence must never read as "nothing matched".** For every factor that fired, the
card shows exactly one of two states: **a span**, or **the explicit "matched text not
available" line** above. There is no third state today. Every current factor is a pattern over
text, so a missing span always means disagreement and must never be absorbed into a
"no span by nature" category. A future factor scored on structure rather than text brings its
own state with its own ADR.

⚠️ **The two states apply only when the re-run actually ran and its result was actually
rendered.** Two cases fall outside them and must not borrow the "not available" line,
because that line asserts a disagreement and neither case observed one:

- **The stored body could not be read** (the existing unreadable-body card, `holds.go`, the
  C46 branch). There is no re-run, so no factor can claim a mismatch. The card keeps its
  existing unreadable-body line, names the factors that fired, and quotes nothing.
- **A span was found but dropped for length.** The card says the matched text was omitted
  for space, and never "the current rules no longer match".

### Rendering constraints

- Each span is fenced and inert, rendered with the same fencing as the body, and labelled
  with the factor it belongs to.
- Spans are bounded: a fixed number per factor and a fixed length per span, with a little
  surrounding context on each side. Zero-width and bidirectional format characters are
  stripped before quoting, using the detector's existing `stripFormatRunes`, so a span
  cannot be made to render differently from what matched.
- The spans share the card's existing Telegram length budget with the body. When space is
  short the **spans win over the body**, because the body is recoverable (next section) and
  the span is the part the operator cannot get elsewhere on the card.

### On-demand expansion to the full message

A span is sometimes not enough context to judge. The hold card therefore gets a
**"Full message"** action that uploads the complete stored body to the operator chat as a
document.

This reuses the existing offloaded-body path for queued outbound mail (ADR 0025:
`sendFullBody`, `fullBodyUploadable` and the Darbaan-authored caption in
`internal/telegram/telegram.go`) rather than new plumbing. The caption must state it is the
full text of the message **under review**, not a file the email carried, exactly as the
outbound caption does.

🚨 **Hard constraint: the expansion terminates at the operator and never reaches an agent.**
A held message is held precisely so that its content does not reach the agent before a
human has judged it. An expansion that delivered the body to an agent — through a tool,
the admin API, or a CLI an agent can run — would hand the payload to exactly the component
the hold protects, and the hold would stop meaning anything. **The operator chat upload is
the only permitted delivery.** A CLI such as `darbaan holds show` must not be offered as
the expansion path on this card, because an agent with shell access can run it.

🚨 **But the button is not the boundary. The credential is.** Any client holding
`holds:read` can already read a held body, and would be able to read the evidence route too.
**ADR 0029's least-privilege example gives a pre-screener "the `*:read` scopes", which includes
`holds:read`.** If an agent ever runs as that pre-screener, it can read exactly the payload the
hold withholds from it, whatever this card does. So:

- **`holds:read` is an operator-only scope.** It must not be granted to any credential an
  agent holds or can reach.
- **ADR 0029's pre-screener example is amended** to the read scopes *excluding* `holds:read`.
  This ADR records that requirement; the amendment itself is a follow-up to 0029.
- Implementation checks the configured clients and confirms that no agent-facing credential
  carries `holds:read` today, rather than assuming it.

## Consequences

- The operator can finally tell a true positive from a message that merely talks about
  the thing a rule looks for, which is what turns approval into a real check rather than
  a judgement on the category of a message.
- The notifier gains a dependency on a span-returning detector method, and the match runs
  twice per held message (once to score, once to render). Holds are rare enough that the
  cost is immaterial.
- A disagreement between the stored verdict and the render-time match becomes **visible**
  on the card instead of silent. That is also a small monitor for ADR 0035: an operator who
  reconfigures patterns will see which older holds no longer reproduce.
- The stored record, the audit log and replay are unchanged.

## Boundaries

- Does not store any message bytes, spans or offsets.
- Does not change scoring, bands, thresholds or which factors exist.
- Does not decide whether the evidence should also appear in the admin CLI or API. If it
  ever does, that is a new ADR, and the hard constraint above applies to it.
- **Revisit trigger, recorded so the decision can be re-judged:** if operator-tuned
  patterns (ADR 0035) remove the motivating false positives at the source, the case for
  carrying attacker text onto the card weakens. A reviewer should check that before
  extending this further.
