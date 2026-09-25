# ADR 0035: Operator-configurable detector patterns

**Status:** Proposed (2026-09-25, pending operator sign-off)

## Context

ADR 0032 introduced injection assessment, and the `assessment:` config section already
makes the *scoring* tunable: `sender_baselines`, `recipient_adjust`, `factor_points`,
`bands` and `threshold` are all operator-set. What the detector actually **matches** is
not. The pattern sets live compiled-in, in English, in `internal/assessor/heuristic.go`
— `instructionPatterns`, `secretsPatterns`, and the hidden-directive and
attachment-directive patterns.

Two consequences follow, and the second is the more serious because it is invisible:

1. **English patterns over-fire on ordinary mail.** Legitimate notification mail has
   been held as a false positive, where "verify"/"confirm" plus a link, or security-code
   text, reads as an instruction or a secrets request. An operator cannot correct this,
   because the only tunable is the factor's weight — and zeroing a factor's points
   disables it for *all* mail rather than fixing the pattern that misfires.
2. **Injection written in another language is not detected at all.** The patterns are
   English, so a non-English instruction or secrets request scores nothing. A deployment
   whose mail is partly German or Persian is unscanned across that portion, and nothing
   in the output distinguishes "assessed and clean" from "assessed with patterns that
   cannot match this language".

A per-sender exception for the source that over-fires is explicitly **not** the fix: it
would key trust to a sender on the content path, duplicate ADR 0031's mechanism in the
wrong layer, and leave the underlying pattern wrong for every other sender.

## Decision

Extend `assessment:` with a `detector:` section:

```yaml
assessment:
  detector:
    instruction:
      mode: augment        # augment | replace
      patterns: ["...", "..."]
    secrets_request:
      mode: replace
      patterns: ["..."]
    hidden_directives:
      enabled: false
```

- **Per-factor pattern lists**, keyed by the same factor names the scorer already uses
  in `factor_points`, so one vocabulary covers both halves.
- **`mode: augment | replace`.** Augment adds to the built-in English set — the expected
  case for adding another language. Replace swaps it, for an operator whose mail the
  defaults suit badly.
- **`enabled: false` disables one factor, or the whole `detector:` block disables
  detection**, as a first-class setting distinct from setting its points to zero.
- **Built-in English patterns remain the defaults** when a factor is not configured, so
  an existing deployment is unchanged by upgrading.
- The isolated `Detector` interface stays as it is; this is configuration plumbed into
  `NewHeuristicDetector`, not a new detector.

## Fail-safe

**An unknown factor name must fail startup, not be ignored.** A misspelled key would
otherwise produce a pattern list that compiles, loads, and matches nothing — a detector
that is silently blind in exactly the way the operator was trying to fix, reporting
clean results the whole time. This is the same class as any probe whose filter cannot
match: the null result is indistinguishable from a real absence.

**An invalid regex must fail startup** for the same reason, rather than being skipped
with a log line that a running deployment will not re-read.

ADR 0032's existing alignment check between detector factors and scorer factors runs
**unconditionally, including when assessment is disabled**, so a misconfiguration fails
at startup instead of waiting for the day the operator enables the feature. That
property must survive this change and extend to operator-supplied factors: the set
validated is the *effective* one after defaults, augments and replacements are applied.

## Consequences

- A false positive becomes fixable rather than tolerated. This matters beyond
  tidiness: a warning layer that over-fires trains an operator to approve through
  warnings, which makes the approval step worse than having no warnings at all.
- Non-English mail becomes scannable, by the operator supplying patterns for the
  languages their deployment actually receives.
- **An operator can now also switch detection off per factor.** That is a real
  loosening, and it is acceptable for the same reason the whole feature is opt-in: the
  assessment layer prioritises and warns, and the approval hold is the control. Nothing
  here changes what is held for an unconfigured deployment.
- Documentation must carry worked non-English examples. Without them the feature is
  technically present and practically unused, which is the state it already exists to
  end.

## Boundaries

- Not a new detector and not a model: the same heuristic matcher over a configurable
  pattern set.
- No per-sender and no per-source exceptions. The unit of configuration is the factor,
  never the correspondent — sender-keyed trust is ADR 0031's concern and belongs there.
- Does not change scoring, bands or the threshold, which are already configurable.
- Does not address whether the matched text is shown to the operator; that is its own
  decision.
