# ADR 0032: Incoming-message injection assessment

**Status:** Proposed (2026-08-07)

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
summary + a coarse risk score** (`low` | `medium` | `high`) describing how likely
the content is an injection/hijack attempt. It **flags and scores; it never
acts** — it cannot approve, send, mark-as-trusted, delete, label, or take any
agent action. Its output is advisory signal, not a decision.

The score reflects *injection risk*, not importance or spam: content that tries to
issue instructions to the reader, impersonate the operator, request credentials or
secrets, or smuggle directives through quoted text or attachments raises the score.
Coarse buckets are deliberate — they avoid false precision and can be refined as
real traffic is seen (the ADR 0005 rationale).

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
and holds no scoped power beyond returning a verdict. It is the deliberate inverse
of the privileged agent: the agent has access but should not read raw attacker
bytes as trusted; the assessor reads the raw bytes but has nothing to hijack.

Only the assessor's **sanitized summary + score** cross the boundary to the
privileged agent — **never the raw payload as an instruction stream**. Even if the
assessor is itself successfully injected, the blast radius is bounded to a wrong
summary/score: it has no capability to act on the injection, and its text output is
delivered onward as clearly-fenced, escaped data (the
[ADR 0006](0006-rejection-as-async-dsn-bounce.md) principle — never echo attacker
text as trusted), never as commands. This is the load-bearing property: **the
gate's safety does not depend on the assessor being uncompromised.** The general
shape is an isolated scoring component that touches the untrusted input but exports
only a verdict across a one-way boundary.

### 3. Route by a source-trust gradient (reuse ADR 0030 / ADR 0031)

Not every message needs full assessment; routing keys on the trust the gate already
stamps (ADR 0030 provenance, ADR 0031 per-sender rules), so assessment effort is
spent where the risk is:

- **Highest trust — operator hand-tagged / labeled mail:** the operator has
  explicitly vouched for this specific message → fast path; assessment can be
  skipped or minimal.
- **Medium — the operator's own authenticated account, auto-flowing** (not
  per-message tagged): reduced assessment.
- **Lowest — other accounts, shared/family boxes, and unknown senders:** →
  **full assessment.**

The gradient is derived from the existing `X-Darbaan-Trust` stamp and per-sender
rules, not re-derived from a spoofable `From` alone. ADR 0031's trust asymmetry
carries over: only an authenticated or explicitly-vouched source earns the fast
path, and an unknown/unauthenticated sender always gets full scrutiny — fail-safe.

### 4. Disposition: low passes, medium and high are held for the human

All three score buckets map to a disposition; the fail-safe default groups the
uncertain middle with the high end:

- **Low risk → pass:** the summary + score travel with the message into the
  agent's view; normal flow.
- **Medium risk → held / flagged for the human (v1 default):** medium is genuine
  uncertainty, so it resolves toward *more* scrutiny, not less — it is held for a
  person exactly like high. Splitting medium off to a lighter disposition (e.g.
  pass-with-prominent-flag) is a policy call the operator can make later via the
  tunable config (§5); v1 holds it. This keeps the coarse three-bucket score from
  leaving any value undispositioned.
- **High risk → held / flagged for the human:** the message is surfaced to the
  operator rather than flowing straight to the agent, so a person decides before
  the agent can act on it.

The human gate remains the backstop for any *consequential* action — defense in
depth. Even a low-scored message that leads the agent toward a real-world action
still meets the outbound sluice's human release (ADR 0003 / ADR 0004). The
assessment lowers the odds an injection reaches the agent unflagged; it never
replaces the human as the final authority.

### 5. The assessment prompt / heuristics are tunable

What counts as "injection-shaped" evolves with attacker technique, so the
assessor's prompt (or heuristic ruleset) is **configuration, tunable over time**
without a core change — the same posture as ADR 0030's config-driven trust and
ADR 0031's rules. The fixed contract is the *shape* — isolation, verdict-only
output, fail-safe routing; the detector inside it is not fixed.

## Fail-safe

Consistent with the inbound trust floor and the outbound sluice, every ambiguity
resolves toward *more* human scrutiny, never less:

- Assessor absent, unreachable, erroring, or timing out → the message is treated as
  **not cleared** (routed as if lowest-trust / held for the human), never
  auto-passed as `low`. A deployment that runs no assessor simply has every
  untrusted message reach the human and agent under the existing trust stamp — the
  assessor can only *add* a flag, never remove the human backstop.
- The assessor can only **raise** scrutiny (flag / hold) or leave the existing
  human gate in place; it has no path to *lower* the outbound human gate.
- Its output is always rendered onward as fenced, escaped data, never executed.

## Consequences

- The automated-risk effort moves to where untrusted content enters (inbound
  injection) and off the outbound path, which stays the simple
  default-block-to-human sluice (ADR 0003) — no outbound risk verdict is built.
- This supersedes the prior send-side 0032 framing (the outbound risk-verdict
  contract), which never landed. ADR 0005's light/strict outbound *routing* is
  untouched but is no longer the target of automated pre-screening.
- The isolation requirement — a zero-access assessor whose only export is a
  verdict — is the security core: the component that reads attacker bytes must have
  nothing to hijack, so a compromised assessor degrades to a wrong score, not an
  action.
- Broader direction: this is one instance of a generic "assess untrusted input in
  isolation, let a human gate any consequential action" pattern; the same shape
  could later gate other agent-actionable inputs. v1 scopes it to inbound mail.
- Scope here is the decision only (Proposed). Implementation — the assessor process
  and its zero-access seam, the trust-gradient routing hook on the ingest/serve
  path, the held/flagged disposition surface, and the tunable prompt config — is
  deferred to follow-up PRs after sign-off.

## Boundaries

- **v1 is read/flag only.** The assessor never mutates the message beyond attaching
  its sanitized summary/score, and never acts. Auto-quarantine or auto-delete of
  high-risk mail is deliberately out of scope — a human decides on a hold.
- **Not an authentication source.** The trust gradient inherits ADR 0031's
  boundary: keying the fast path on sender identity is only as strong as the
  upstream's sender authentication; unknown/unauthenticated senders always get full
  assessment, so a spoofed `From` reaches the fast path only under the same
  conditions ADR 0031 already bounds.
- **The assessor is not the gate.** It reduces how much untrusted content reaches
  the agent unflagged; the human release on the outbound sluice remains the
  authority for any consequential action.
