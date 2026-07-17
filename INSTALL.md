# Installing Darbaan with Docker

This is the full, from-scratch guide to running Darbaan as a mail gate using
Docker Compose. By the end you will have Darbaan reading your mailbox over IMAP
and holding outbound mail for your approval over SMTP.

## 1. Prerequisites

- **Docker** and the **Docker Compose plugin** (`docker compose version`).
- An **upstream mailbox** you want to gate, plus credentials for it. For Gmail
  this means an **app password** (with 2-Step Verification enabled on the
  account); a normal password will not work for IMAP/SMTP.
- (Optional) A **Telegram bot token** and your Telegram user ID, if you want to
  approve outbound mail from your phone.
- A shell with `openssl` for generating the TLS and signing keys below.

## 2. Get the code

```sh
git clone https://github.com/yaad-index/darbaan.git
cd darbaan
```

Everything below is run from the repository root.

## 3. Create the secrets

Darbaan never bakes secrets into the image — they are mounted from `./secrets/`
and read from `.env`. Create the key material first.

### TLS (required unless you explicitly allow plaintext)

The agent connects to Darbaan over STARTTLS. For a trusted-LAN / localhost
deployment a self-signed certificate is fine:

```sh
mkdir -p secrets/tls
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout secrets/tls/key.pem -out secrets/tls/cert.pem \
  -days 3650 -subj "/CN=darbaan.local"
```

(For a localhost-only first run you can instead skip TLS — see the
`DARBAAN_LISTENER_ALLOW_INSECURE` note in `docker-compose.yml` — but TLS is the
default and recommended path.)

### DKIM signing key (for trustworthy bounces)

When Darbaan rejects a send it returns a **DKIM-signed bounce**, so the agent can
trust it. Generate an ed25519 key:

```sh
mkdir -p secrets/dkim
openssl genpkey -algorithm ed25519 -out secrets/dkim/dkim.pem
```

Publish the matching public key as a DKIM `TXT` record for your bounce domain
(selector `darbaan` by default), so signatures verify:

```
darbaan._domainkey.<your-bounce-domain>   TXT   "v=DKIM1; k=ed25519; p=<base64-public-key>"
```

Extract the public key with:

```sh
openssl pkey -in secrets/dkim/dkim.pem -pubout -outform DER | tail -c 32 | base64
```

## 4. Configure `.env`

```sh
cp .env.example .env
```

Edit `.env` and set:

| Variable | Required | Purpose |
|---|---|---|
| `DARBAAN_AGENT_PASS` | yes | the agent's login password to Darbaan's IMAP/SMTP faces |
| `DARBAAN_ADMIN_TOKEN` | yes | bearer token for the localhost-only admin API (approval) |
| `DARBAAN_SMTP_PASSWORD` | to deliver | upstream app password (only when sending is switched on) |
| `DARBAAN_INBOUND_IMAP_PASSWORD` | to read | upstream app password for the mailbox to sync |
| `DARBAAN_FACE_BIND` | optional | `0.0.0.0` to reach the faces from a trusted LAN; default `127.0.0.1` |
| `DARBAAN_TELEGRAM_TOKEN` | for Telegram | bot token for the phone approval client |
| `DARBAAN_TELEGRAM_OPERATOR_ID` | for Telegram | your Telegram user ID (only this user may approve) |

The agent username defaults to `agent` (set in `docker-compose.yml`).

## 5. Choose what's switched on (in `docker-compose.yml`)

Darbaan is **safe by default**: it sends nothing and syncs nothing until you opt
in. In the `darbaan` service's `environment:`:

### Outbound delivery (default: stub = nothing leaves)

```yaml
DARBAAN_SENDER_TYPE: "smtp"            # was "stub"
DARBAAN_SMTP_HOST: "smtp.gmail.com:587"
DARBAAN_SMTP_USERNAME: "you@gmail.com"
# DARBAAN_SMTP_PASSWORD comes from .env
```

While `sender-type=stub`, submissions are still held and approvable, but an
approved message is **not actually delivered** — a deliberate safety default.

### Inbound sync (default: off)

```yaml
DARBAAN_INBOUND_IMAP_HOST: "imap.gmail.com:993"
DARBAAN_INBOUND_IMAP_USERNAME: "you@gmail.com"
DARBAAN_INBOUND_IMAP_MAILBOX: "INBOX"
DARBAAN_INBOUND_MAX_AGE: "1y"          # only sync mail newer than this
# DARBAAN_INBOUND_IMAP_PASSWORD comes from .env
```

`inbound-max-age` is **forward-only**: widening it later requires a re-sync.

**Optional inbound filter.** You can gate what the client sees: mount a YAML
rules file and point at it with `DARBAAN_INBOUND_FILTER`. Rules match on message
fields and **allow**, **hide**, or **hold-for-human** each message (those are the
literal action values), with a configurable default. Left unset, the client sees the full synced mailbox. Note
that a configured filter means the client's inbox may intentionally show fewer
messages than the real mailbox.

### Bounce identity

```yaml
DARBAAN_DKIM_SELECTOR: "darbaan"
DARBAAN_DKIM_DOMAIN: "<your-bounce-domain>"
```

### Telegram approval (optional)

The Telegram client lets you approve or reject held mail from your phone. To set
it up:

1. **Create a bot.** In Telegram, open a chat with **@BotFather**, send
   `/newbot`, and follow the prompts. BotFather replies with a **bot token** —
   put it in `.env` as `DARBAAN_TELEGRAM_TOKEN`.
2. **Find your user ID.** Message a bot such as **@userinfobot**; it replies with
   your numeric Telegram user ID. Put it in `.env` as
   `DARBAAN_TELEGRAM_OPERATOR_ID`. **Only this user ID can approve or reject** —
   any other person who messages the bot is ignored.
3. **Start the chat.** Send `/start` to your new bot once, so Telegram allows the
   bot to message you.

With both values set, the `darbaan-telegram` container polls the admin API and
sends you a message for each held outbound item, with **Approve** / **Reject**
buttons; tapping one decides that message and the buttons clear. It holds no mail
credentials and only talks to the localhost admin API — it is purely a remote
control for the approval queue.

If you do not want phone approval, leave these two values unset and remove the
`darbaan-telegram` service from `docker-compose.yml`; the CLI (section 8) approves
mail on its own.

## 6. Start it

```sh
docker compose up -d --build
```

This starts two containers: `darbaan` (the SMTP + IMAP faces and the
localhost-only admin API) and `darbaan-telegram` (the optional phone approval
client; harmless if you have not set a token, but you can remove that service
from the compose file if unused).

Check it came up:

```sh
docker compose ps
docker compose logs darbaan | tail
```

You should see a line reporting the SMTP, IMAP, and admin addresses, and (if
enabled) the inbound sync target and interval.

## 7. Verify the faces

The agent faces are published on:

- **IMAP** `<host>:1143` — read mail
- **SMTP** `<host>:1465` — submit mail

(`<host>` is `127.0.0.1` by default, or the LAN address if you set
`DARBAAN_FACE_BIND=0.0.0.0`.) Connect with any IMAP/SMTP client using the agent
username/password over STARTTLS. The admin API on `127.0.0.1:1144` is **not**
published to the network and is for the operator only.

## 8. Approving outbound mail

Submitted mail is **held** until you approve it. Two operator interfaces:

**CLI** (runs inside the container, authenticates via the admin token it
inherits):

```sh
docker exec darbaan-darbaan-1 darbaan queue ls          # list held + decided
docker exec darbaan-darbaan-1 darbaan queue approve <id>
docker exec darbaan-darbaan-1 darbaan queue reject <id> --reason "not allowed"
# reject requires --reason; add --retryable to mark it a transient failure
```

**Telegram**: once `DARBAAN_TELEGRAM_TOKEN` + `DARBAAN_TELEGRAM_OPERATOR_ID` are
set, the `darbaan-telegram` container messages you on each held item with
approve/reject buttons.

## 9. End-to-end smoke test

1. Submit a message through the SMTP face (any SMTP client, agent creds, STARTTLS).
2. `docker exec darbaan-darbaan-1 darbaan queue ls` — it shows `pending`.
3. Approve it (CLI or Telegram).
4. With `sender-type=smtp` it is delivered; reject one instead and a
   **DKIM-signed bounce** appears in the IMAP inbox.

## 10. Troubleshooting

- **`AUTHENTICATIONFAILED` to the upstream** — the app password is wrong or
  revoked, or 2-Step Verification is not enabled on the upstream account.
- **Agent can't connect / connection refused from another host** — set
  `DARBAAN_FACE_BIND=0.0.0.0` and recreate (`docker compose up -d`); by default
  the faces bind to localhost only.
- **Approved mail doesn't arrive** — `sender-type` is still `stub`; flip it to
  `smtp` and set the username + `DARBAAN_SMTP_PASSWORD`.
- **TLS errors on a self-signed cert** — the client must accept the self-signed
  certificate (or use a real one); for a localhost-only trial you can enable the
  insecure-plaintext option noted in `docker-compose.yml`.
- **Bounce won't verify** — confirm the DKIM `TXT` record matches the generated
  public key and the configured selector/domain.
- **Is inbound sync healthy?** — `docker exec darbaan-darbaan-1 darbaan sync-status`
  reports each fronted account's last successful sync, consecutive-error count, UID
  watermark, and whether it is **stalled**. A stalled account also emits a loud
  `account sync stalled` log event, so a persistent stall is visible without
  reading the per-cycle log line by line.

## Configuration reference

The full list of settings (file `<` env `<` flag precedence) is available from:

```sh
docker exec darbaan-darbaan-1 darbaan --help
```
