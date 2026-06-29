# ADR 0024: Inbound bounce-spoof guard — hide unsigned DSN-shaped mail by default

**Status:** Proposed (2026-06-29)

> Numbering note: ADR 0023 is reserved for the multi-inbox ADR (referenced by
> ADR 0022); this guard was specified first and takes 0024.

## Context

ADR 0006 made rejections arrive as **inbound DSN/bounce mail**. ADR 0007 named the
attack and the trust anchor: an outsider can mail a **forged MAILER-DAEMON** to
push the agent into resending elsewhere or acting on a fake failure, so Darbaan
**signs every bounce it issues** (DKIM over a dedicated signing domain/selector,
pinned public key on the agent) and an agent trusts **only** a Darbaan-signed
bounce. ADR 0007 also said, in prose, that Darbaan "quarantines any external mail
posing as a bounce" — but it never specified **how that quarantine is detected,
where it runs, or what it does**. With the serve-time filter now built (ADR
0021) and per-inbox visibility incoming (ADR 0022), this ADR makes the quarantine
concrete.

## Decision

Add a **built-in inbound bounce-spoof guard**: a message that **looks like a
bounce/DSN** but does **not** carry a valid Darbaan signature (ADR 0007) is
**hidden from the agent by default**. The guard is **on by default** and runs as a
**serve-time view** (ADR 0021), consistent with the rest of inbound filtering —
the store keeps everything (ADR 0019); the agent simply doesn't see spoofs.

### Bounce-shaped detection

A message is **bounce-shaped** if **any** of these hold. `Shaped()` reads only the
message headers + MIME structure (no upstream fetch beyond having the raw bytes in
hand). But **which of these signals are cheap at the lazy read face** differs (see
*Read-face wiring* below): at SELECT only the **envelope From** is available without
a body fetch; the other signals need the raw message.

- `Content-Type: multipart/report` with `report-type="delivery-status"`, or a
  `message/delivery-status` part declared in the structure;
- envelope/header **From is the null sender `<>`** or a `MAILER-DAEMON@` /
  `postmaster@` local-part;
- `Auto-Submitted: auto-replied` (RFC 3834) combined with a delivery-status
  content type.

These are heuristics for the **shape** of a bounce, deliberately broad: the guard's
job is to catch anything *posing* as a bounce, and the trust check (below) is what
actually decides.

### Trust check (ADR 0007)

A bounce-shaped message is **trusted** only if it carries a **valid DKIM signature
from Darbaan's own bounce signing domain/selector** (the key Darbaan signs with in
`internal/signer`). Darbaan holds that key, so it can verify its own signature
inbound. A genuine Darbaan-issued bounce verifies and passes through (the agent
**must** still receive its real failures — ADR 0006). Any bounce-shaped message
without that valid signature is a **spoof candidate**.

**Verification needs the body (bounded on-demand fetch).** Unlike the rest of the
serve-time filter (ADR 0021), DKIM verification is **not metadata-only**: the
signature's body-hash (`bh=`) covers the message body, so verifying it requires the
body. For a **shape-positive** record still lazy/unfetched (ADR 0019), the guard
triggers an **on-demand body fetch** to run the verify. This is a deliberate,
**bounded** exception: only **bounce-shaped** messages (a small subset, identified
cheaply from metadata first) ever incur the fetch — ordinary mail never does.
Verification reuses the DKIM library already in deps (`go-msgauth/dkim`) via a
`signer.Verify` against the pinned bounce selector.

### Read-face wiring (lazy interaction)

The read face (ADR 0019) is **lazy**: at SELECT/list, records carry metadata only
(`Raw` is nil) and the body is fetched on demand. Because **most shape signals and
the verify need the raw message**, running the full guard at SELECT would fetch
every body and defeat lazy. So v1 wires it as:

1. a cheap **envelope-From pre-check** at the read face — null sender `<>` /
   `MAILER-DAEMON` / `postmaster`, the only shape signal available without a fetch;
2. on a From hit, a **bounded on-demand raw fetch** → full `Shaped()` + `signer.Verify`;
   non-bounce-From records pass with **no fetch**;
3. opportunistically, the full guard also runs when `Raw` is **already in hand**
   (fetched for any reason) — free tightening, no extra fetch.

This closes ADR 0007's **named attack** (a forged `MAILER-DAEMON`/`postmaster`
bounce) while preserving lazy. **Documented gap (v1):** a `multipart/report` DSN
from a **non-daemon** From is not caught at the read face — it does not impersonate
the mailer daemon, so it is not the named threat; full shape coverage is the
follow-up below. (Implementer review surfaced this constraint: the trust check
cannot be metadata-only, and at the lazy read face only the envelope From is.)

### Action

- **Spoof candidate → `hide` by default.** The record stays in the store
  (auditable, ADR 0011/0019) but is omitted from the read face — the agent never
  sees it.
- The guard runs **ahead of the user filter rules** (ADR 0021/0022), so a spoof
  cannot be accidentally surfaced by a permissive default (`default_visibility:
  visible`) or a broad allow rule. It is a **security floor**, not a user rule.
- **Operator-configurable, secure by default:**

  ```yaml
  bounce_guard:
    enabled: true                 # default true
    on_spoof: hide | hold-for-human   # default hide
  ```

  `hold-for-human` routes spoof candidates to the inbound approval queue (ADR
  0021) instead of silently hiding — useful while tuning. `enabled: false` is an
  explicit operator opt-out (logged). Genuine signed bounces are **never** caught
  regardless of setting.

## Boundaries / non-goals

- **Not anti-injection in general.** This guard addresses the specific forged-bounce
  vector of ADR 0007; the outbound trap (ADR 0003) remains the containment boundary
  for everything an *allowed* sender might say.
- **No body content matching.** Shape detection uses envelope/structure metadata
  only; we never parse or pattern-match the human-readable bounce text. (The DKIM
  trust check reads the body to compute its hash, but that is cryptographic
  verification, not content matching.)
- **Not DMARC/SPF.** The trust anchor is Darbaan's **own** signature (ADR 0007), not
  the upstream's authentication of the purported origin. We are answering "did
  Darbaan issue this bounce?", not "is this a legitimate third-party bounce?".

## Consequences

- ADR 0007's quarantine promise becomes an enforced, testable behavior with a
  defined detection set, evaluation point, and action.
- The agent's bounce-handling (ADR 0006) only ever sees Darbaan-signed bounces; the
  forged-resend attack is closed at the read face, not left to agent vigilance.
- Composes cleanly with per-inbox visibility (ADR 0022): the guard is a built-in
  pre-rule floor; user `default_visibility` + rules apply to whatever the guard
  lets through.
- Detection is heuristic-broad; the trust check (signature) is the precise gate, so
  broad shape-matching causes no false hides of genuine (signed) bounces — only
  unsigned bounce-shaped mail is affected.

## Follow-ups

- **Full read-face shape coverage** (closes the v1 non-daemon-From gap): store a
  bounce-shape flag in inbox metadata, computed when a body is fetched, so SELECT can
  shape-check the flag and fetch raw only to verify on a hit. Spans the sync + inbound
  store (a data-model add), so it is deferred past the v1 wiring. Must spell out how
  the flag is populated for never-yet-fetched records (compute on first fetch, guard
  re-checks then) so an unfetched non-daemon DSN is not silently surfaced forever.
- Surface a count of guarded spoofs in audit/admin so the operator can see the guard
  working (and tune `on_spoof`).
- Revisit if a legitimate need arises to show *third-party* bounces (e.g. for an
  inbox that genuinely sends outbound through another MTA) — would be a per-inbox
  opt-in, not a default change.

Relates to ADR 0003, 0006, 0007, 0011, 0019, 0021, 0022.
