# Darbaan

Darbaan is a **mail-gate proxy**. An agent talks to it over standard **IMAP
(read)** and **SMTP (send)**, and Darbaan enforces policy mechanically in front
of the real mailbox. It holds the upstream mailbox credentials and the
bounce-signing key, so a compromised agent only ever holds *Darbaan* credentials
— never the real mailbox (credential isolation, [ADR 0002](adr/0002-policy-in-a-separate-box-credential-isolation.md)).

The design is recorded as Architecture Decision Records in [`adr/`](adr/) — start
with [ADR 0001](adr/0001-mail-proxy-not-http-api.md).

## Outbound — default-deny send

An agent submits over SMTP; nothing leaves until it's approved.

1. **Sluice trap.** Every submission is trapped in a default-deny sluice
   ([ADR 0003](adr/0003-outbound-sluice-trap-default-deny.md)) — held, not sent.
2. **Approval.** A pluggable approval chain ([ADR 0004](adr/0004-pluggable-approval-pipeline.md))
   decides each held message. Approval is operator-driven (see the clients below).
3. **Release or reject.** On approval Darbaan sends via the upstream; on rejection
   it returns a **DKIM-signed DSN bounce** ([ADR 0006](adr/0006-rejection-as-async-dsn-bounce.md),
   [ADR 0007](adr/0007-signed-bounce-trust.md)) that the agent reads back over IMAP.

> The upstream sender is **stub by default** — it sends *nothing*. Real delivery is
> a deliberate opt-in (`sender-type=smtp` + an app password); until then the
> default-deny holds structurally.

## Inbound — read the real mailbox, gated

The agent reads its real mail *through* Darbaan ([ADR 0019](adr/0019-inbound-sync-store-canonical-lazy-no-filter.md)):

- **Store-canonical incremental sync.** Darbaan pulls from the upstream mailbox
  into its own store (UIDVALIDITY + cursor, idempotent re-sync). The upstream is
  read-only except for label writes (below).
- **Lazy content.** Headers/envelopes are synced eagerly; a message **body is
  fetched on demand** the first time it's read, then cached. Listing the inbox
  fetches zero bodies.
- **Recency cutoff.** `inbound-max-age` (e.g. `1y`) bounds the sync to recent mail
  ([ADR 0008](adr/0008-inbound-filter-yaml-rules.md), recency dimension), so a
  deep mailbox doesn't pull decades of history.
- **IMAP read face.** The synced mail is served back over IMAP.
- **Agent labeling.** The agent labels mail via standard IMAP keywords
  ([ADR 0020](adr/0020-agent-labeling-gmail-x-gm-labels.md)); on a Gmail backend
  those map to real **X-GM-LABELS** (searchable as `label:...`), with the local
  store canonical and the backend an eventually-consistent label replica.

> The structured allow/hide/hold **inbound filter rules** (the rest of ADR 0008)
> are still upcoming; v1 syncs the (recency-bounded) mailbox without per-message
> rule evaluation.

## Interfaces — clients over a local admin API

`serve` runs the SMTP + IMAP faces and a **localhost-only admin API**. The
operator-facing interfaces are **separate processes** that talk to that API
([ADR 0017](adr/0017-interfaces-as-clients-over-local-api.md)), not compiled into
the core:

- **CLI** — `darbaan queue …` inspects and decides held messages.
- **Telegram** — `darbaan telegram` notifies + approves/rejects from a phone.

## Storage

Tiered ([ADR 0018](adr/0018-tiered-storage-metadata-kv-content-filesystem.md)):
message metadata lives in bbolt; raw content lives as filesystem blobs, written
blob-first then metadata so a crash can only orphan a blob (swept at startup).
The store is the canonical source; the IMAP/SMTP faces are translation adapters
([ADR 0016](adr/0016-store-canonical-translation-faces.md)). An append-only audit
log ([ADR 0011](adr/0011-append-only-audit-log.md)) records decisions.

## Running it

Darbaan is a single Go binary; the easiest deploy is Docker Compose. See
[`docker-compose.yml`](docker-compose.yml) and [`.env.example`](.env.example).

```sh
cp .env.example .env        # fill DARBAAN_AGENT_PASS, DARBAAN_ADMIN_TOKEN
# put a TLS cert+key in ./secrets/tls/ and an ed25519 DKIM key in ./secrets/dkim/
docker compose up -d
```

Key configuration (file `<` env `<` flag; full list via `darbaan --help`):

| Setting | Env | Purpose |
|---|---|---|
| agent credential | `DARBAAN_AGENT_USERNAME` / `DARBAAN_AGENT_PASS` | the agent's IMAP/SMTP login to Darbaan |
| admin token | `DARBAAN_ADMIN_TOKEN` | bearer token for the localhost admin API |
| sender | `sender-type` (`stub`/`smtp`) + `DARBAAN_SMTP_PASSWORD` | upstream delivery; **stub by default** |
| DKIM | `DARBAAN_DKIM_KEY_FILE` / `dkim-selector` / `dkim-domain` | bounce signing |
| inbound sync | `DARBAAN_INBOUND_IMAP_HOST` / `…_USERNAME` / `DARBAAN_INBOUND_IMAP_PASSWORD` | upstream mailbox to sync (empty = sync off) |
| recency cutoff | `inbound-max-age` (e.g. `1y`) | bound the initial sync to recent mail |

Ports bind to `127.0.0.1` only — Darbaan is a local-trusted-host service, not
internet-facing. Secrets come from env/mounts, never the image
([ADR 0012](adr/0012-deployment-and-secrets-at-rest.md)).

## License

MIT — see [LICENSE](LICENSE).
