# ADR 0031: Per-sender trust rules

**Status:** Proposed (2026-07-23)

## Context

ADR 0030 shipped inbox-level trust (slices 1–5): a whole mailbox is stamped with one `X-Darbaan-Trust` level. That is too coarse — it is a property of the *channel*, which a consumer could largely derive itself, not of *who sent a given message*. The value the operator actually needs is **per-sender** trust: act on the operator's own addresses, explicitly flag a known device (a scanner-to-email box) as not-to-act-on, and leave everything else unclassified.

This is sound only under the boundary the README `[!CAUTION]` (#209) now states: darbaan is not an authentication source, but the **upstream** mail server authenticates senders (SPF/DKIM/DMARC/spam). When the upstream enforces sender auth (e.g. Gmail on its own domain), keying trust on the `From` is meaningful because a spoofed sender never reaches the inbox darbaan reads. Point darbaan at an upstream that doesn't, and a `From` is forgeable — so this ADR's central job is to make per-sender trust *no less safe than* that boundary, and to offer a way to harden past it.

The three levels all get real use here:
- **trusted** — a known-good sender (the operator's own addresses): the agent may act on it.
- **untrusted** — a KNOWN source that must NOT be acted on (a device / scanner address): flagged, treat with precaution, report to the operator. Distinct from unknown.
- **unknown** — no rule matched (the default): unclassified, not safe to act.

## Decision

Add a configurable, per-inbox list of **trust rules**, each matching on the sender and resolving to a level plus an optional note, reusing ADR 0030's `Stamp{Trust, Note}` and the strip/stamp/serve chokepoint unchanged — **only the trust-determination input widens**, from (inbox) to (inbox, sender).

### The trust asymmetry (the load-bearing decision)

`trusted` is the only dangerous outcome — it tells the agent it may act. `untrusted` and `unknown` are the cautious side; an attacker gains nothing by spoofing a `From` into them. So the auth requirement is asymmetric:

- **untrusted / unknown** outcomes are applied from the matched `From` directly. No authentication gate — they only ever *withhold* trust.
- **trusted** elevation is sound only when the `From` is authenticated. Two modes:
  - **Upstream-trust (v1 default).** Rely on the upstream's own sender-auth + spam-filtering, exactly the README boundary: the operator chose an upstream that authenticates, so a spoofed `From` doesn't reach the inbox. Simple; correct for a strong upstream (Gmail); its safety is the operator's upstream choice, and the README states it plainly.
  - **Authentication-Results gate (opt-in `require_authenticated`, recommended for weaker upstreams).** Elevate to `trusted` only if the upstream `Authentication-Results` shows **`dmarc=pass`** for the message's `From` domain — DMARC pass already requires SPF-or-DKIM *alignment* with the `From`, which is exactly the property that matters. For an upstream that doesn't emit a `dmarc=` result, the fallback is an **aligned `dkim=pass`**: a verified DKIM signature whose `d=` domain matches the `From` domain. A bare `dkim=pass` — a valid signature from *any* domain — is **not** sufficient (it doesn't bind to the `From`). On failure the sender resolves to `unknown`, never `trusted`. Defends even if a spoofed `From` reaches the inbox.

**The trusted `authserv-id` is an operator-configured, REQUIRED value per upstream** (e.g. Gmail's `mx.google.com`) — there is **no default that trusts any/all authserv-ids.** This is the load-bearing bit: `Authentication-Results` is **not** in darbaan's stripped `X-Darbaan-*` namespace, so a sender *can* inject their own `Authentication-Results: bogus.example; dmarc=pass`. The gate therefore reads **only** the `Authentication-Results` header(s) whose `authserv-id` equals the configured trusted value — the identity the upstream MTA stamps — and ignores **every** other one, forged or not. Without a configured trusted `authserv-id` (or if the upstream adds none), `trusted` elevation is simply **unavailable** for that inbox and every sender falls back to `unknown` — the gate fails safe, never open. This makes the gate's own input unspoofable in the same way the write-path anchor is.

**Decided in review:** design the Authentication-Results gate now and ship it as the opt-in **slice 2**, with **slice 1** being the upstream-trust model — a strong-upstream operator (Gmail) gets immediate value and a weak-upstream operator can harden. The From-based match is a deliberate, bounded relaxation of ADR 0030's "never from message content" — bounded by this asymmetry, so it never *elevates* trust on unauthenticated content.

### Rule shape

A `rules` list on the existing per-inbox `trust` block (ADR 0030 slice 2). The block's `level` becomes the **default** applied when no rule matches; `note`/`body_banner` are unchanged.

```yaml
inboxes:
  - name: work
    trust:
      level: unknown                 # ADR 0030: the no-rule-match default
      require_authenticated: true    # gate: only elevate to trusted on verified auth
      authserv_id: mx.google.com     # the upstream MTA's Authentication-Results identity;
                                     # REQUIRED for the gate — no default, forged ones ignored
      rules:
        - from: ops@example.com
          level: trusted
          note: "operator address"
        - from_domain: scanner.local
          level: untrusted
          note: "device address — do not act; report to the operator"
```

`require_authenticated` + `authserv_id` gate the `trusted` outcome only; both are optional (omitting them selects the upstream-trust default). `untrusted`/`unknown` are unaffected by the gate.

Each rule is `{ matcher, level, note? }`. `level` is validated against the three values; `note` reuses the slice-3 length/control-char validation.

### Matching + precedence

- Match on the message `From` address, normalized (lower-cased, RFC 5321 address).
- **Granularity (v1):** exact address (`from`) or domain (`from_domain`). Pattern/regex matching is a later extension (Boundaries).
- **Precedence: most-specific-wins** — an exact-address rule beats a domain rule for the same sender. This is order-independent (deterministic regardless of config order). Within a tier a sender can match at most one rule; duplicate matchers are rejected at load, so there is no ambiguity to break.

### Composition with the per-inbox default (ADR 0030)

Resolution order for a message: **most-specific matching per-sender rule → the inbox's default `level` (slice 2) → global `unknown`**. A matched rule supplies both level and (if set) its note; with no rule match the inbox's own `level`/`note` apply as before. Per-sender rules thus strictly *refine* the inbox default; removing all rules is exactly ADR 0030 behavior.

### Integration — reuse the ADR 0030 chokepoint

`provenance.Sanitize(raw, Stamp)` and the write chokepoint (`putBlob`) + serve-path backstop are unchanged. The only change is upstream of them: the resolver widens from `func(inbox) Stamp` to a lookup over `(inbox, sender)` — it reads config only (rules + default), extracting the `From` (and, under the gate, the trusted `Authentication-Results`) from the raw. The chokepoint parses the `From` from the raw headers, resolves the `Stamp`, then stamps as today.

Write-path and serve-path stay consistent because both derive from the **same** stored `From` (and the serve-path is still keyed on the authenticated selected inbox for *which* rule set applies). Re-deriving the same trust from the same headers keeps it idempotent, so the serve-path backstop still gives legacy blobs their real per-sender trust and stays fresh on a config change.

## Boundaries

- **v1 matches `From` only.** Subject / other-header criteria are a later extension.
- **Address + domain matching only in v1.** Glob/regex patterns are deferred (a larger validation + precedence surface).
- **Not a replacement for the upstream's authentication** — this pairs with the README `[!CAUTION]` (#209). Per-sender `trusted` is only as sound as the upstream. If the upstream doesn't authenticate senders (and, under the gate, doesn't add a trustworthy `Authentication-Results` from the configured `authserv-id`), then `trusted` elevation simply isn't available for that inbox — every sender falls back to `unknown`. Darbaan never manufactures trust the upstream didn't earn.
- **Authentication-Results parsing is bounded** to the configured `authserv-id` and DMARC/DKIM domain alignment; full RFC 8601 method coverage is not a v1 goal.
- **Rules are per-inbox.** A global/shared sender-rule set is a possible later addition; v1 keeps rules under the inbox that already owns the trust default.
- **A `from_domain` rule trusts *every* sender at that domain** — even under the gate, which only verifies the domain is authentically the sender's, not that the sender is the intended one. So a `trusted` `from_domain` on a **public** domain (`gmail.com`) trusts anyone with an address there; **exact-address rules are the safe pattern for public domains.** This is a config-review concern, not enforced by darbaan.

## Consequences

- Operators get precise, auditable per-sender trust — act on `ops@`, flag the scanner as untrusted, default the rest to unknown — and all three levels earn their place.
- The trust input now reads the `From` (message content), a deliberate relaxation of ADR 0030's inbox-only anchor. It is bounded so it can never *raise* trust on unauthenticated content: the cautious levels need no auth, and `trusted` is gated by the upstream (or the Authentication-Results check).
- Everything downstream of trust determination — the strip/stamp invariant, the note, the banner, the serve-path backstop — is reused unchanged, so this rides the audited ADR 0030 plumbing.
- A misconfiguration is a config-review concern (a too-broad `trusted` domain rule), auditable in one place per inbox.

## Slices

1. **Per-inbox rules + resolution (matched on `From`, upstream-trust model).** Parse + validate the `rules` list (level, matcher, note; reject duplicate matchers); resolve most-specific rule → inbox default → unknown; widen the chokepoint's trust input to `(inbox, From)`. Delivers trusted/untrusted/unknown for a strong upstream, reusing the ADR 0030 chokepoint.
2. **Authentication-Results gate for `trusted`** (opt-in `require_authenticated`): trusted `authserv-id` config, DMARC/DKIM alignment check, forged-`Authentication-Results` defense; gate failure → `unknown`.
3. **(Later)** richer matchers (pattern/regex), additional match criteria, and/or a global rule set.
