# Darbaan

**Darbaan is a mail-gate proxy.** An agent (or any client) talks to it over
standard **IMAP** to read mail and **SMTP** to send mail, and Darbaan enforces
policy in front of the real mailbox. Darbaan holds the upstream mailbox
credentials and the bounce-signing key, so a compromised client only ever holds
*Darbaan* credentials — never the real mailbox.

Two properties define it:

- **Outbound is default-deny.** Nothing a client submits is sent until a human
  approves it.
- **Inbound is gated.** The client reads a synced, recency-bounded view of the
  real mailbox, never the live account directly.

## Outbound — nothing leaves without approval

A client submits a message over SMTP, and:

1. **It is held.** Every submission is trapped in a default-deny sluice — queued,
   not sent.
2. **A human decides.** An operator approves or rejects each held message through
   one of the approval clients (below). The client never approves its own mail.
3. **Release or bounce.** On approval Darbaan delivers via the upstream provider
   and signs the message; on rejection it returns a **DKIM-signed bounce** that
   the client reads back over IMAP and can cryptographically trust.

The upstream sender is **stub by default** — it delivers *nothing*. Real delivery
is a deliberate opt-in, so the default-deny holds even before any policy is
configured.

## Inbound — read the real mailbox, gated

- **Synced into Darbaan's own store.** Darbaan pulls from the upstream mailbox
  incrementally (idempotent re-sync); the upstream is read-only except for label
  writes.
- **Lazy content.** Envelopes and headers sync eagerly; a message body is fetched
  on first read and then cached, so listing the inbox downloads no bodies.
- **Recency cutoff.** A configurable max age bounds the sync to recent mail, so a
  deep mailbox doesn't pull years of history.
- **Served over IMAP** as a single `INBOX`.
- **Labeling.** A client labels mail with standard IMAP keywords; on a Gmail
  backend these map to real Gmail labels (searchable as `label:...`), with
  Darbaan's store canonical and the backend an eventually-consistent replica.

## Approval clients

Darbaan's core runs the SMTP + IMAP faces and a **localhost-only admin API**. The
operator-facing tools are separate processes that talk to that API, not compiled
into the core:

- **CLI** — `darbaan queue …` lists and decides held messages.
- **Telegram** — approve or reject from your phone (setup in [INSTALL.md](INSTALL.md)).

Each client authenticates with a bearer token. By default that's a single shared
`DARBAAN_ADMIN_TOKEN`; optionally, give each client its own least-privilege,
independently-revocable token via `admin_clients:` (see `config.example.yaml` and
adr/0029).

## Install / run

Darbaan is a single Go binary; the easiest deployment is Docker Compose. See
**[INSTALL.md](INSTALL.md)** for a complete, from-scratch walkthrough (secrets,
configuration, switching on delivery and inbound sync, approving mail, and an
end-to-end smoke test).

The short version:

```sh
cp .env.example .env        # fill DARBAAN_AGENT_PASS, DARBAAN_ADMIN_TOKEN
# put a TLS cert+key in ./secrets/tls/ and an ed25519 DKIM key in ./secrets/dkim/
docker compose up -d
```

The agent faces bind to `127.0.0.1` by default (set `DARBAAN_FACE_BIND=0.0.0.0`
to reach them from a trusted LAN); the admin API is always localhost-only.

## Design notes

The architecture and the reasoning behind each decision are recorded as
Architecture Decision Records in [`adr/`](adr/), for those who want the detail.
They are reference material — you do not need them to run or use Darbaan.

## License

MIT — see [LICENSE](LICENSE).
