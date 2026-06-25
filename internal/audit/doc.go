// Package audit is the append-only, hash-chained audit log keyed by agent
// identity: every queued draft, verdict, approver, retry, and both the original
// and any human-edited draft. The hash chain makes tampering or truncation
// evident (ADR 0011).
package audit
