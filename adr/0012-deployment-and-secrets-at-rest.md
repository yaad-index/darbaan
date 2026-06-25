# ADR 0012: Deployment and secrets at rest

**Status:** Accepted (2026-06-25)

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
