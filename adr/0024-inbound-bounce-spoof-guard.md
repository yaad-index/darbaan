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

A message is **bounce-shaped** if **any** of these hold (metadata only — no body
fetch, consistent with ADR 0021):

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
- **No body matching.** Detection uses envelope/structure metadata only (ADR 0021);
  it does not parse the human-readable bounce body.
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

- Surface a count of guarded spoofs in audit/admin so the operator can see the guard
  working (and tune `on_spoof`).
- Revisit if a legitimate need arises to show *third-party* bounces (e.g. for an
  inbox that genuinely sends outbound through another MTA) — would be a per-inbox
  opt-in, not a default change.

Relates to ADR 0003, 0006, 0007, 0011, 0019, 0021, 0022.
