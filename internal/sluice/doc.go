// Package sluice is the outbound hold/queue: the trap every submitted message
// enters. Submission is accepted (250 OK) and enqueued; nothing auto-sends. The
// default disposition is block (default-deny) and the queue is fail-closed — an
// unapproved message waits forever and never decays into "send later"
// (ADR 0003).
package sluice
