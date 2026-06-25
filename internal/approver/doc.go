// Package approver is the approval registry and pipeline. Approvers implement
// one contract, (message + metadata) -> verdict, are selectable at compile time
// and runtime, and chain for multi-level approval where every stage must pass.
// Timeout is fail-closed: a message with no verdict stays queued, never sends
// (ADR 0004, 0005).
package approver
