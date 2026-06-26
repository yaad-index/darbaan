# ADR 0018: Tiered storage — metadata in the KV store, message content on the filesystem

**Status:** Proposed (2026-06-26)

## Context

v1 stores each message's full raw RFC 822 (headers + body + attachments) as a
single bbolt value. bbolt memory-maps its file and loads a value into memory on
access — fine for small messages, but a poor fit for large attachments or a
GB-scale inbound mailbox: big values cause memory spikes and file bloat, and
bbolt is built for many small keys, not blob storage.

ADR 0015 put persistence behind the `MessageStore` interface precisely so the
engine could change without rewiring call sites. This is that change.

## Decision

Split each stored message into two tiers:

- **Metadata → the KV store (bbolt).** Per message: id, agent, from, rcpt,
  subject, status, thread references, size, received-at, and a **blob
  reference**. All small; bbolt is good at this.
- **Raw content → the filesystem.** The full raw RFC 822 bytes (headers + body
  + attachments) are written as a **blob** under the data volume
  (`<data>/blobs/`), keyed by message id, referenced from the metadata record.
  The bytes never sit in bbolt.

This applies to **all message stores** — the outbound sluice and the inbound
store (so even a 25 MB outbound attachment never lands in bbolt). The
`MessageStore` interface is unchanged; the split is internal to the
implementation, so nothing above the store layer (faces, admin API, telegram
client) cares where the bytes live.

The **audit log stays untiered** — its entries are small metadata and remain in
their own bbolt store (ADR 0011). Only the message stores tier their content.

Blob keying is **one blob per message id** (deleted with the message). Content
addressing / cross-message dedup is a possible future optimization, not v1.

## Crash consistency

Write order is **blob first, then the metadata record** that references it. So:

- Crash after the blob write but before the metadata write → an orphan blob (no
  metadata points to it). Harmless; reclaimable by a sweep that deletes blobs
  with no referencing metadata.
- A metadata record therefore always points to an existing blob — never a
  dangling pointer.

This drops the single-transaction atomicity of the old inline-value write; the
metadata record remains the source of truth, and the ordering guarantees no
reader ever sees a pointer to missing content.

## Consequences

- bbolt stays small (metadata only) regardless of mailbox size or attachment
  size; large content never goes through its mmap / value-load path. GB-scale
  inbound becomes viable: metadata in bbolt + blobs on disk you'd store anyway.
- Composes with lazy inbound sync (a later ADR): metadata can exist before its
  content blob, so headers can be synced eagerly and bodies/attachments fetched
  on demand into the blob store.
- Two writes per message instead of one; see crash-consistency above for why
  that's safe.
- At-rest protection of the blobs follows ADR 0012 (the data volume; full
  message-store encryption remains future scope and would cover blobs too).
- A future store backend (SQLite, object store) still satisfies `MessageStore`;
  the tier split is a property of the bbolt-backed implementation, not the
  interface.

## Follow-ups

- Implement the tiered sluice store first (it's live), then reuse the pattern
  for the inbound store.
- Orphan-blob sweep (reclaim blobs with no referencing metadata).
- Relates to ADR 0015 (storage abstraction), ADR 0011 (audit untiered),
  ADR 0012 (secrets/at-rest), ADR 0016 (store-canonical).
