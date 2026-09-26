# ADR 0012: Deployment and secrets at rest

**Status:** Accepted (2026-06-25); amended 2026-09-26 (see the end)

## Context
Darbaan holds every mailbox's real credentials and its bounce-signing key. A
disk image or repo leak must not yield usable secrets. It is not yet hardened to
face the open internet.

## Decision
Darbaan runs on a **local trusted host** and is **not** published as an
internet-ready service in v1. Upstream credentials and the signing key are
**encrypted at rest** (age/sops or OS keyring); the decryption key is supplied
**at startup**; secrets live in memory only while running. Nothing secret is
stored plaintext on disk or in the repo.

## Consequences
- A stolen disk image or leaked repo yields nothing usable.
- **Post-v1:** full at-rest encryption of the entire message store, not just secrets.

## Amendment (2026-06-25, review)
**Resolving the two open choices.** At-rest encryption uses **age** (portable,
scriptable, simple file-based identities) rather than an OS keyring — keyring
support can come later as an option. The **startup decryption key** is delivered
as an **age identity file** whose path is given via config/env, or an
interactive passphrase prompt; the key/identity is never written by Darbaan and
lives in memory only while running.

## Amendment (2026-09-26): plaintext secrets on disk are the accepted posture

Decision on items A18 and C18 of #237; text above stays as written (ADR 0037).

The Decision above requires secrets to be encrypted at rest with age. Nothing
implements it: every secret (agent password, admin token, upstream app passwords,
Telegram token, DKIM key) is plaintext in an environment file or key file. The ADR
must not claim a protection that does not exist, so **plaintext on disk is recorded as
the accepted posture**, with these requirements:

- secret files are readable by their owner only (mode 0600 or stricter);
- the service runs as a dedicated user that owns them;
- secrets are never committed to a repository.

Encryption at rest is not implemented now. A service that starts unattended must keep
its decryption identity on the same disk as the encrypted secrets, so on one host it
mostly protects against a reader who can already read the identity. It stays open as a
future option if the secrets move to an OS keyring or a KMS, where the key genuinely
lives elsewhere.
