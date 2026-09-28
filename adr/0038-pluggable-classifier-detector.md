# ADR 0038: A pluggable classifier detector beside the pattern detector

**Status:** Proposed

## Context

ADR 0032 fixed the *shape* of inbound assessment: an isolated component reads the
untrusted content and reports **which named factors it sees**, never a number; the
system composes the score from a configurable point-table. It also said the detector
inside that shape is not fixed.

Today the only detector is the pattern detector (`internal/assessor/heuristic.go`,
made operator-configurable by ADR 0035). Patterns have two limits that configuration
cannot remove:

1. **They match wording, not intent.** An instruction or a credentials request that is
   phrased in a way no pattern anticipated scores nothing, and a legitimate message that
   happens to use the anticipated words scores high.
2. **They are per-language.** ADR 0035 lets an operator add patterns for other
   languages, but every language needs its own set, and coverage is only ever as wide as
   the sets someone wrote.

Small non-generative **classifiers** now exist: they take a piece of text and return a
label with a confidence, and nothing else. They are not language models: there is no
prompt, no generated text, and nothing in the input can be read as an instruction to them.
They run locally, on CPU or a modest GPU, at a per-message cost low enough for every inbound
message. That makes a classifier a practical second detector without changing anything
ADR 0032 fixed.

## Decision

### 1. Detectors compose; the pattern detector stays the base

The assessor accepts **a list of detectors** instead of one. Each implements the existing
`Detector` interface (`Detect` returns flagged factors; `Factors` declares which factors it
can flag). The assessor runs them and takes the **union** of the flagged factors, then
filters, de-duplicates and scores exactly as today.

- The **pattern detector is always present** and runs first. It is the floor: a
  deployment with no classifier configured behaves exactly as it does now.
- A **classifier detector is optional**, enabled by configuration.
- Union is deliberate: a detector can only *add* flags. A classifier can never clear a
  factor the patterns flagged, so adding one cannot lower any message's score. That keeps
  the change on the fail-safe side of ADR 0032.

### 2. A classifier, not a language model: text in, labels out, flags only

The classifier detector sends the message's extracted text to the classifier and gets back
**labels with confidences**. There is no prompt and no generated output. A configured
**mapping from classifier label to factor**, with a confidence threshold per label, turns
the labels into flagged factors. The detector returns **factors only, never a score, a
summary or free text**, so it fits ADR 0032's flags-only contract as-is and its output
cannot carry attacker text across the boundary.

The label-to-factor mapping and the thresholds are **configuration**, in the same
`assessment.detector` section ADR 0035 introduced, so they are tunable without a release.
A general-purpose language model behind a prompt is explicitly **not** this detector: it
reintroduces the instruction-following surface the assessor exists to avoid.

### 3. The classifier runs behind a local endpoint, and is never the privileged process

The detector calls a classifier server over a local HTTP endpoint (operator-configured
URL). The classifier runs in its own process with no mail credentials, no store access and
no send path, which is ADR 0032 section 2 applied to a new component. The first supported
backend is a local open-weight classifier; the endpoint shape does not tie the detector to
one.

**Mail content is never sent to a third-party hosted classifier by default.** A hosted
endpoint is possible in principle, but it would move untrusted and private content off the
operator's machines, so it needs an explicit operator setting and is not the default.

### 4. A classifier failure holds the message, exactly as an assessor failure does today

ADR 0032's fail-safe already says an assessment that errors or times out is **not cleared**,
and the screener holds such a message today. A configured classifier is part of that
assessment, so the same rule applies unchanged: if the classifier endpoint times out, errors,
or returns something unparsable, **the assessment fails and the message is held
(NotCleared)**. It is never replaced by a weighted factor, because any weight low enough to
be tuned would let through mail that the current code holds.

- The classifier gets **its own timeout, nested inside** the assessor's, so a slow classifier
  fails the assessment explicitly rather than consuming the whole budget.
- The assessment's list of **active factors includes the classifier's factors only when the
  classifier actually ran**, so a result never implies coverage it did not have.
- Trading holding for availability (patterns-only when the classifier is down) would change
  ADR 0032's fail-safe, so it is out of scope here and would need an amendment to 0032.

### 4b. Each flagged factor records which detector flagged it, and the classifier's evidence

The assessment result records, **per flagged factor, the detector that flagged it**. For a
classifier hit it also records the **label and confidence** that produced it. ADR 0036 builds
held-message evidence by re-running the *patterns* at render time, which finds nothing for a
factor only the classifier flagged; the recorded label and confidence are what the held card
shows for those factors instead. They are metadata about the classification, never text from
the message, so they carry no attacker content across the boundary.

### 5. Scope: open question for the maintainer

ADR 0032 set spam and importance aside and scoped assessment to injection. As written, this
ADR keeps that scope: the classifier's labels map onto the **same named factors** the
pattern detector flags. **Whether to add spam or phishing as factors is left to the
maintainer's review of this ADR**, because it changes what a high score *means* and who acts
on it. If accepted, it is one added paragraph here plus new entries in the point-table; the
mechanism above does not change.

## Fail-safe

- No classifier configured: identical to today.
- Classifier configured and healthy: flags can only be added, never removed.
- Classifier configured and failing: the assessment fails and the message is held, the same
  outcome ADR 0032 already gives an assessor failure.

## Consequences

- Coverage stops depending on anticipated wording and on one pattern set per language, for
  the factors the classifier's labels map to.
- A new runtime dependency exists when enabled: a classifier server that must be deployed,
  sized and monitored. Its latency adds to assessment time at ingest.
- False positives can rise, because union can only add flags. The per-factor confidence
  threshold and the existing point-table are the tuning levers.
- An operator can tell a pattern hit from a classifier hit when tuning (section 4b).
- A classifier outage holds every incoming message it would have assessed, so the classifier
  server needs the same monitoring as the gate itself.

## Boundaries

- Not decided here: which classifier, its size, or the deployment unit. That is an
  implementation and operations choice behind the endpoint.
- Left to review: spam or phishing factors (see section 5).
- Not changed: scoring, bands, thresholds, sender baselines, recipient adjustment, or the
  isolation rules of ADR 0032.
