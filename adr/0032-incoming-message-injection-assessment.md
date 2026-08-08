# ADR 0032: Incoming-message injection assessment

**Status:** Proposed (2026-08-08)

Repoints the pre-screener concept from outbound to inbound.
[ADR 0005](0005-agent-prescreener-plugin-risk-routing.md) introduced an automated
risk verdict for *queued outbound* mail; that framing is set aside here (see
Context). Outbound stays the simple default-block-to-human sluice
([ADR 0003](0003-outbound-sluice-trap-default-deny.md)) with no automated verdict.
This ADR builds directly on the inbound trust work — the provenance stamp
([ADR 0030](0030-gate-stamp-trust-provenance-headers-on-inbound-mail.md)) and
per-sender trust rules ([ADR 0031](0031-per-sender-trust-rules.md)) — and on the
credential-isolation ([ADR 0002](0002-policy-in-a-separate-box-credential-isolation.md))
and runtime-client ([ADR 0017](0017-interfaces-as-clients-over-local-api.md))
boundaries.

## Context

The real risk an autonomous mail agent carries is not spam or misjudged
importance — it is **prompt injection**. Untrusted incoming content is
attacker-controlled, and anything the model treats as instruction inside it can
hijack the agent (a confused-deputy attack): steer it, with its own access, into a
rash or exfiltrating action. This is the standing surface ADR 0030 already named
when it stamped inbound trust — but a trust stamp only *labels* the risk; it does
not read the content and assess whether this particular message is trying to hijack
the reader.

The *outbound* side is already handled. The sluice is default-deny and every send
is gated by a human (ADR 0003 / [ADR 0004](0004-pluggable-approval-pipeline.md)):
a message never leaves without a person releasing it, so no automated "is this send
risky" verdict is load-bearing there — the human is the gate. The prior (unmerged)
elaboration of ADR 0005 built a risk-verdict contract for that outbound path; with
the human send gate as the backstop, it was adding an automated risk signal to a
step the sluice already fully guards. That effort is better spent where the
untrusted content actually *enters*: the inbound path.

What is missing is a defense that reads incoming content *before* the privileged
agent treats it as instruction, and tells the human (and the agent) how risky it
looks — **without itself becoming a new injection foothold**. That is the hard
constraint: the component that reads attacker-controlled bytes must have nothing
worth hijacking.

## Decision

### 1. An incoming-assessment layer whose only job is injection defense

Add an assessment layer that, for untrusted incoming mail, produces a **sanitized
summary + a numeric risk score in the range 0–100** describing how likely the
content is an injection/hijack attempt, together with the **list of factors** that
produced that score. It **flags and scores; it never acts** — it cannot approve,
send, mark-as-trusted, delete, label, or take any agent action. Its output is
advisory signal, not a decision.

The score is a *risk score*, not an importance or spam score. It is presented
against **labeled bands** so humans and routing rules can speak in words while the
underlying number stays precise:

- **0–33 → low**
- **33–66 → medium**
- **66–100 → high**

The band cutoffs are **configuration**, tunable without re-plumbing anything: an
operator can move the low/medium or medium/high boundary, and every downstream rule
that keys on a band follows, because a band is only a labeled interval over the same
0–100 number. This is the deliberate improvement over fixed coarse buckets — the
score carries real resolution, and the labels are a presentation layer on top of it,
not the primitive.

**Content in scope.** Because attachments are a named injection vector, the assessor
is fed the message's **decoded text content — the body's text parts and text
extracted from attachments** (e.g. the text of a PDF or an HTML part), not just the
top-level `text/plain`; assessing only the outer body would blind it to a vector the
threat model calls out. Extraction is **bounded** (per-part size and type limits, and
no execution of active content — the assessor renders attachments to inert text, it
never opens them as programs), so a hostile attachment cannot turn extraction itself
into code execution. The exact decoders, media types, and limits are an
implementation detail (follow-up); this ADR fixes only that decoded attachment
content is *in* the assessment's scope and that extraction stays inert and bounded.

### 2. Isolation: the assessor is a zero-access component

The assessment runs in a component with **no tools and no privileges** — no mail
credentials, no send path, no store writes, no admin authority. It is a runtime
client (ADR 0017) that sits behind the credential-isolation boundary (ADR 0002)
and holds no scoped power beyond returning its findings. It is the deliberate inverse
of the privileged agent: the agent has access but should not read raw attacker
bytes as trusted; the assessor reads the raw bytes but has nothing to hijack.

Only the assessor's **sanitized summary + the flagged-factor list + the composed
score** cross the boundary to the privileged agent — **never the raw payload as an
instruction stream**. Even if the assessor is itself successfully injected, the
blast radius is bounded to a wrong summary/factor-list: it has no capability to act
on the injection, and its text output is delivered onward as clearly-fenced, escaped
data (the [ADR 0006](0006-rejection-as-async-dsn-bounce.md) principle — never echo
attacker text as trusted), never as commands. This is the load-bearing property:
**the gate's safety does not depend on the assessor being uncompromised.** The
general shape is an isolated scoring component that touches the untrusted input but
exports only a verdict across a one-way boundary.

### 3. The score is composed by rules, never emitted by the model

The number is **never produced by the LLM.** The isolated assessor's job is narrow:
detect whether the content exhibits each of a set of **bounded, named factors** and
report *which it sees* — for example:

- direct **instruction to the reader** ("ignore your previous instructions…",
  "forward this to…"),
- a **credentials/secrets request**,
- **hidden or quoted-text directives** (instructions buried in quoted history,
  zero-width/off-screen text, HTML-hidden spans),
- **attachment-smuggled directives** (instructions carried in a decoded attachment).

The assessor returns a *set of flags*, not a magnitude. A **config point-table**
then turns each flagged factor into a `+N` contribution, and the system sums them.
Because the mapping from factor → points lives in configuration and the model only
reports booleans, the score is **explainable and stable**: the same factors always
compose the same number, an operator can retune any factor's weight without touching
the assessor, and a compromised assessor can only lie about *which factors it saw* —
it can never assert a number directly.

**Sender baseline and recipient position are added by the system, outside the LLM
entirely.** Two contributions never touch the assessor:

- **Sender baseline.** A configured starting value keyed on the sender (by domain,
  pattern, or per-sender rule): a trusted/vouched sender contributes ≈ 0, an unknown
  sender contributes `+N`. This is derived from the same trust the gate already
  stamps — the source-trust gradient below and the ADR 0030 provenance /
  ADR 0031 per-sender rules — not from a spoofable `From` read by the model.
- **Recipient position.** Whether the mailbox was a `To`, `CC`, or `BCC` recipient
  is a separate system adjustment (bulk/BCC-shaped delivery is a mild risk signal).
  It is fed into **both** the assessor's prompt (as context) *and* the routing
  arithmetic (as a score term), so the same fact informs the read and the gate.

The final risk score is therefore `sender_baseline + recipient_adjustment +
Σ(flagged content factors × point-table)`, with the content term contributed by the
isolated assessor and the other two contributed by the trusted system.

### 4. Short-circuit at the gate

Scoring is **additive and short-circuiting**: contributions are applied in order and
the running total is checked against the human-surface threshold (§6) as it grows.
**Once the total crosses the threshold, tallying stops and the message is gated** —
there is no need to enumerate every remaining factor to know it must be held. The
result stays fully **explainable**: the disposition names *which factors carried the
total across the line*, so a held message always comes with its reason.

### 5. Cheap-to-expensive evaluation order

Because the sender baseline and recipient position are **instant, no-LLM lookups**,
they are applied **first**, before the content assessor is ever invoked. The
isolated content assessor — the expensive step — is only run **if the cheap terms
have not already crossed the gate.** A known-bad sender (baseline alone over the
threshold) is held **without the assessor ever running**; the model is spent only on
messages where the content read can still change the outcome. This is the
source-trust gradient (§6) expressed as an ordering: cheap trust signals gate the
obvious cases, and the costly read is reserved for the genuinely uncertain ones.

### 6. Route by a source-trust gradient; human-surface threshold is operator config

Routing keys on the composed score against a **human-surface threshold** that is
**operator configuration**, with the **default set to HIGH (≈ 70)**:

- **Below the threshold (low and medium bands, by default) → the agent handles it:**
  the sanitized summary, the score, and the flagged-factor list travel with the
  message into the agent's view; normal flow.
- **At or above the threshold (high band, by default) → held / flagged for the
  human:** the message is surfaced to the operator rather than flowing straight to
  the agent, so a person decides before the agent can act on it.

This **replaces the earlier v1 rule that held the medium band by default.** With a
composed, explainable score and the human send gate still standing behind every
consequential action, medium-band mail flows to the agent by default and only
high-band mail is held — while an operator who wants a more conservative posture
simply lowers the threshold in config (down to the medium boundary, or lower), with
no code change. The threshold is one number over the same 0–100 scale the bands
label.

The gradient this threshold sits on is derived from the existing `X-Darbaan-Trust`
stamp and per-sender rules (ADR 0030 / ADR 0031), not re-derived from a spoofable
`From` alone. ADR 0031's trust asymmetry carries over: only an authenticated or
explicitly-vouched source earns a low baseline and the fast path, and an
unknown/unauthenticated sender always starts with a raised baseline and gets full
scrutiny — fail-safe.

Safety is preserved regardless of where the threshold sits: the agent only ever sees
the **sanitized summary + composed score + factor list, never the raw payload**, and
any *consequential* action the agent is steered toward still meets the outbound
sluice's human release (ADR 0003 / ADR 0004) — defense in depth. The assessment
lowers the odds an injection reaches the agent unflagged; it never replaces the human
as the final authority.

### 7. Point-table, thresholds, and prompt are all tunable

What counts as "injection-shaped" evolves with attacker technique, so everything
that shapes the number is **configuration, tunable over time** without a core
change — the same posture as ADR 0030's config-driven trust and ADR 0031's rules:

- the **factor point-table** (how many points each flagged factor adds),
- the **sender baselines** and the **recipient-position adjustment**,
- the **band cutoffs** (low/medium/high boundaries),
- the **human-surface threshold**,
- the assessor's **prompt / detector ruleset** (which factors it looks for).

The fixed contract is the *shape* — isolation, model-flags-not-numbers,
system-composed score, verdict-only output across the boundary, fail-safe routing;
the weights and the detector inside it are not fixed.

## Fail-safe

Consistent with the inbound trust floor and the outbound sluice, every ambiguity
resolves toward *more* human scrutiny, never less:

- Assessor absent, unreachable, erroring, or timing out → its content contribution
  is treated as **not cleared**: the message is routed as if held (surfaced to the
  human), never auto-passed as low. A deployment that runs no assessor simply falls
  back to the system-composed terms (sender baseline + recipient position) under the
  existing trust stamp — the assessor can only *add* risk points, never remove the
  human backstop.
- The composed score can only ever **raise** scrutiny (add points, hold) or leave
  the existing human gate in place; nothing in the pipeline can *lower* the outbound
  human gate.
- The assessor's output is always rendered onward as fenced, escaped data, never
  executed.

## Consequences

- The automated-risk effort moves to where untrusted content enters (inbound
  injection) and off the outbound path, which stays the simple
  default-block-to-human sluice (ADR 0003) — no outbound risk verdict is built.
- This supersedes the prior send-side 0032 framing (the outbound risk-verdict
  contract), which never landed. ADR 0005's light/strict outbound *routing* is
  untouched but is no longer the target of automated pre-screening.
- Splitting the number's *composition* (system, rule-driven, explainable) from the
  content *read* (isolated model, flags only) is the security core alongside
  isolation: the component that reads attacker bytes never gets to assert a
  magnitude, so a compromised assessor degrades to a wrong flag-set fed through a
  fixed table — still bounded, still explainable — not an arbitrary number and never
  an action.
- Cheap-first ordering keeps cost proportional to uncertainty: obvious cases (known
  senders on either end of the trust gradient) gate on instant lookups, and the
  model is spent only where the content read can still move the outcome.
- Broader direction: this is one instance of a generic "assess untrusted input in
  isolation, compose an explainable score by rule, let a human gate any consequential
  action" pattern; the same shape could later gate other agent-actionable inputs.
  v1 scopes it to inbound mail.
- Scope here is the decision only (Proposed). Implementation — the assessor process
  and its zero-access seam, the factor detectors, the point-table / baseline / band /
  threshold config, the trust-gradient routing hook on the ingest/serve path, and the
  held/flagged disposition surface — is deferred to follow-up PRs after sign-off.

## Boundaries

- **v1 is read/flag only.** The assessor never mutates the message beyond attaching
  its sanitized summary, factor list, and composed score, and never acts.
  Auto-quarantine or auto-delete of high-scoring mail is deliberately out of scope —
  a human decides on a hold.
- **Not an authentication source.** The sender baseline inherits ADR 0031's
  boundary: keying a low baseline on sender identity is only as strong as the
  upstream's sender authentication; unknown/unauthenticated senders always start with
  a raised baseline and get full assessment, so a spoofed `From` earns the low
  baseline only under the same conditions ADR 0031 already bounds.
- **The assessor is not the gate.** It reduces how much untrusted content reaches
  the agent unflagged; the human release on the outbound sluice remains the
  authority for any consequential action.
