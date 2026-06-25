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
