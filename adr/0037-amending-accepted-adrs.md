# ADR 0037: Amending accepted ADRs

**Status:** Proposed (2026-09-26, pending operator sign-off). Supersedes the immutability sentence of ADR 0000.

## Context

ADR 0000 says ADRs are immutable once Accepted and that a later ADR can supersede an
earlier one. The set has not worked that way since its first day. Dated `## Amendment`
sections appended to accepted ADRs are the established practice, starting with ADR
0002 on 2026-06-25, and at least a dozen ADRs carry one. The practice is sound: a
narrow correction does not warrant a new ADR, and appending keeps the original
reasoning readable.

Two things have gone wrong around it, and both come from the rule not describing the
practice:

- **Prior text has been edited in place.** ADR 0013's original "Go 1.24" text was
  rewritten rather than amended, so the decision as first accepted is no longer in
  the file. On 2026-09-26 ADR 0035's example configuration was corrected in place.
  An in-place edit leaves no trace in the document of what the decision said before.
- **Amendments are easy to miss.** An amendment at the bottom of a long ADR can
  correct a sentence in its Decision section, and a reader who stops at the Decision
  never learns the sentence is wrong.

## Decision

1. **An accepted ADR may be amended by appending a dated section**, headed
   `## Amendment (YYYY-MM-DD): <what it changes>`. An amendment may correct, narrow
   or extend the ADR. A change that reverses the decision is a new ADR that
   supersedes this one, as ADR 0000 already says.
2. **Text above an amendment is never edited**, including errors, examples and
   citations. A correction goes in an amendment that quotes or names what it
   corrects. That is what keeps the document an honest record of what was decided
   and when.
3. **The Status line is the one field that changes in place.** It records the
   current state (Proposed, Accepted, Superseded by NNNN) and **lists the date of
   every amendment**, so a reader sees at the top that later text changes earlier
   text. For example: `**Status:** Accepted (2026-06-25); amended 2026-06-27,
   2026-09-26.`
4. **An amendment to an accepted ADR needs the same sign-off as an ADR** (the
   maintainer's approval), because it changes a recorded decision.
5. **A Proposed ADR is a draft and may be edited freely; rules 1 to 3 apply from
   the moment it is Accepted.** One caution: a Proposed ADR whose code has already
   shipped is no longer only a draft, because that code was built against its text.
   An edit to one is allowed, but it goes in a PR of its own that says what changed,
   rather than riding along inside an unrelated change.

The in-place edits named above stay as they are: undoing them would be another
in-place edit. Git history records the original text of each.

## Consequences

- The rule now describes how the set is actually maintained, so a reviewer can apply
  it rather than work around it.
- Corrections cost slightly more reading, since the reader follows the Status line to
  the amendments. That is the price of an honest record.
- Every ADR that has amendments but no amendment dates on its Status line is out of
  step with this rule until its Status line is updated, which is itself a Status-line
  change and allowed.

## Boundaries

- Does not change which decisions need an ADR, or the numbering scheme.
- Does not reopen any past decision.
