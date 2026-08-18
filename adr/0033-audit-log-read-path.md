# ADR 0033: Reading the audit log — live over the admin API, with a dedicated scope

**Status:** Proposed (2026-08-18, pending operator approval)

Gives the append-only audit log ([ADR 0011](0011-append-only-audit-log.md)) a
**read** path. It rides the loopback admin API ([ADR 0017](0017-interfaces-as-clients-over-local-api.md))
and extends the per-client scope vocabulary ([ADR 0029](0029-admin-per-client-scoped-tokens.md))
with a new `audit:read` capability. It touches the access model
([ADR 0002](0002-policy-in-a-separate-box-credential-isolation.md) least authority;
[ADR 0003](0003-outbound-sluice-trap-default-deny.md) sluice surface), which is why
the transport choice — the part that moved during review — is recorded here rather
than settled in code.

## Context

ADR 0011 gave the audit log two operations: `Append` (write, hash-chained) and
`Verify` (prove integrity). It has **no way to read what it holds**. The data that
answers "which agent did what, as which inbox, when" is written and tamper-evident
and unreachable.

This surfaced as a real incident. A batch of messages entered the hold queue and
the process log was silent across exactly the window in which they were submitted,
while logging loudly either side of it — because every decision transition logged
and the enqueue path logged nothing. That silence read as *nothing happened* and
sent the reader hunting for an external cause. The narrow half of that gap — the
missing arrival line — is closed separately (the enqueue path now logs). This ADR
is the larger half: even with the arrival audited, an operator **cannot read the
audit record back** to reconstruct where a held message came from.

There is an obvious-looking answer that is wrong. `Verify` already opens the log
through `OpenReadOnly`, and a read command sitting beside it would inherit that
open. But `OpenReadOnly` takes bbolt's shared lock and **fails while `serve` holds
the exclusive write lock — you must stop `serve` first**. So an audit reader built
that way can only answer once the mail gate is down. That defeats the motivating
case exactly: the incident is *live* — the one moment you do not want to stop the
gate is while you are trying to understand what it is doing.

`verify` and a listing command look like siblings because they share the noun
"audit", but they are opposite in use. `verify` is deliberate, scheduled
maintenance that genuinely wants a quiescent file. A listing is incident response,
reached for while things are on fire. Inheriting `verify`'s offline constraint
treats them as the same kind of command because of the shared noun.

The right precedent is already in the codebase: `queue` listing and `sync-status`
read **live** state through the running `serve`'s loopback admin API. And `serve`
already holds the audit log open — the admin service carries the live audit sink it
uses today to append inbound-hold verdicts. A read capability on that existing,
already-wired handle is *less* new plumbing than a fresh offline open, not more.

## Decision

### 1. The read path is the live admin API, not an offline open

Add a read capability to the audit backend and expose it as an admin-API route
(`GET /audit`) on the same loopback, token-authenticated server that already serves
queue listing and `sync-status`. It reads the **in-process** audit handle `serve`
already holds, so it answers while the gate runs. The reader is an enumeration over
the hash chain in sequence order (the same walk `Verify` performs, without the
integrity assertions); filtering (by message id, agent, time range) and paging sit
on top of it.

### 1a. Bound the read transaction, not the HTTP response

Moving the enumeration into the live process changes what "stream it" may mean, and
this is a consequence of the transport rather than an implementation detail. `Verify`
walks the whole chain inside one `db.View` today, and that is safe only because it
runs offline with nothing appending. In the live process the same single-transaction
walk would have a **client-paced lifetime**: the read transaction stays open as long
as the HTTP client is consuming. That opens two distinct failure modes, and they
differ in severity:

- **Growth (disk).** bbolt cannot reclaim pages a read transaction is using — its
  transaction documentation warns that a long-running read transaction can make the
  database grow quickly. A slow reader would grow the audit database of a *running*
  gate; a read causing unbounded growth.
- **Writer stall (liveness), the more serious mode.** A long-lived read transaction
  can also stall the writer's periodic memory-map maintenance, so an unbounded read
  can block *appends*. This is not a tidiness cost — it is the gate losing the ability
  to audit while a reader is open. A reviewer who saw only the growth cost might
  reasonably decide to accept it; the liveness cost is what makes bounding
  non-optional.

Therefore the decision is to **bound the transaction, not the response**, which
closes both modes at once: each page is served from a fresh, short `db.View`. The
page token carries a **resume position** — the last sequence number emitted — not a
live cursor object; a bbolt cursor's keys and values are valid only inside their
originating transaction, so each page re-derives its position with a `Seek` to the
next key rather than resuming a saved cursor. Streaming becomes a property of the
paged HTTP response, never of a single database snapshot; no read transaction
outlives one page. Two costs are accepted out loud:

- The enumeration is **no longer a single point-in-time snapshot**. Because the log
  is append-only and seq-ordered, a seq-keyed cursor still guarantees no prior entry
  is missed or duplicated across pages; the only effect is that entries appended
  *during* a multi-page walk may or may not appear, which is acceptable for reading
  history.
- A narrow filter **still walks the whole chain** — filtering happens over the
  enumeration, it does not avoid the scan. This stays a latency property, not a
  scan-avoidance one. (The offline path, if ever built, would not face the growth
  concern and could use the single `db.View` walk — the growth risk is specific to
  the live transport.)

`verify` is untouched. Integrity checking wants a quiescent file, so it keeps its
own offline command and its `OpenReadOnly` path. Only *listing* moves to the live
surface.

### 2. A dedicated `audit:read` scope, not a ride on `queue:read`

`GET /audit` requires its **own** scope, `audit:read`, added to the ADR 0029 route
→ scope map (the valid-scope set derives from that map, so the vocabulary extends
by adding the route). It is deliberately **not** folded into `queue:read`.

The audit log is the historical record of who-did-what-as-which-inbox across **all**
events — enqueue, verdicts, sends, rejects — over the life of the deployment. That
is a strictly larger disclosure than `queue:read`, which shows only the messages
currently held. A least-privilege client granted `queue:read` to triage the live
queue must not thereby inherit the entire history. Giving audit reading its own
capability keeps ADR 0029's least-privilege promise intact: an interface that
should not see the historical record simply is not granted `audit:read`.

### 3. No redaction in v1

Audit output over the admin API carries the record's fields as written — agent,
inbox, actor, message id, event, detail. It is **not** redacted.

The earlier argument for not redacting rested on file possession ("anyone who can
run the reader already holds the database file, so redacting the output is
theater"). That argument is **retired** with the offline transport: under the admin
API the control is a loopback token plus a scope, not possession of the file, and
"you could read the bbolt directly anyway" no longer holds.

The argument that survives the transport is **surface consistency**. This same
loopback, token-authenticated admin surface already carries strictly more sensitive
data than an audit record: queue inspection returns full raw RFC822 message
**bodies** (ADR 0002/0003 access model). Agent and inbox strings in an audit record
are not a new category of exposure for a surface that already serves message
bodies. And redaction *inside* a granted scope would be either theater or a sign the
scope is drawn wrong — the access decision **is** the scope (§2). If a caller should
not see agent/inbox, the answer is to withhold `audit:read`, not to grant it and
blank the fields the capability exists to serve.

An optional redacted/`--redact` form — for exporting a chain excerpt outside the
gate, e.g. into a support ticket — is a handling concern orthogonal to transport and
is **deferred**, not part of v1.

### 4. "Audit disabled" and "backend cannot list" are distinct operator states

Two different conditions must produce two different messages, never one generic
failure:

- **Audit is disabled** — the deployment runs the `null` backend, or no audit sink
  is wired (e.g. a single-agent deployment or a test). There is no chain; there is
  nothing to read.
- **The backend cannot list** — a registered backend that implements append/verify
  but not the read capability. The chain exists; this build cannot enumerate it.

Collapsing these into one error would reproduce, in the read path itself, the exact
failure that motivated the whole effort: an absence that reads as a *different*
absence and sends the operator to the wrong cause. The command must say which of the
two it hit.

## Consequences

- Incident response can read audited arrivals **live**, without taking the mail gate
  down — the case the audit log was failing to serve.
- The core gains a small surface: a read capability is one method on the audit
  handle the admin service already holds, plus one route and one scope. The offline
  reader that was considered would have added a separate open path.
- The scope vocabulary grows by one (`audit:read`), and least privilege is preserved:
  historical-record access is grantable and revocable independently of live-queue
  triage.
- **Known limitation, recorded here as a trade-off rather than found later:** in v1
  there is **no offline enumeration at all** — not merely an unexposed one. `verify`
  can prove integrity but cannot list, and the new enumeration is reachable only
  through the live admin API. So when `serve` itself is wedged or down — which can be
  exactly when an operator most wants the log — the audit log is unreadable again,
  the very condition #292 set out to end, now narrowed to the outage case. v1 accepts
  this. Closing it later is cheap and additive: the same enumeration primitive over
  `verify`'s `OpenReadOnly` gives a separate offline command, and offline it does not
  face the growth concern of §1a (nothing is appending), so it can use the simple
  single-`View` walk. It is deliberately deferred, not designed out. Naming the gap
  in the decision keeps it a known consequence of shipping the live path first, not a
  defect discovered after.
- No redaction means the admin API's audit output carries agent/inbox/detail —
  consistent with the message bodies the same surface already serves. An operator who
  moves an excerpt *outside* the gate (a ticket, an issue) should treat it with the
  same care as a message body; the deferred `--redact` form is the future lever if a
  routinely-shareable form is wanted.
