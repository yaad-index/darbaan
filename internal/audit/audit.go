// Package audit is Darbaan's pluggable, optional audit log. An AuditLog records
// what happened — enqueue, verdicts, send attempts — and can prove the
// integrity of what it holds. It is selected by config (audit.type): "null"
// turns auditing off for a simple single-agent deployment; "bbolt" is the
// hash-chained, tamper-evident log (ADR 0011).
//
// Audit is its own store, separate from the message store, and entries are
// written AFTER the message-store commit. It is therefore best-effort: the
// message store is the source of truth, and a crash between the two writes can
// only ever leave a "missing audit" gap, never a phantom message. See
// AuditLog.Verify for what integrity does and does not cover.
package audit

import (
	"fmt"
	"sort"
)

// Record is the caller-supplied content of an audit entry. Agent + Inbox are the
// acting principal and the inbox it acted as (ADR 0027): every row answers "which
// agent did what, as which inbox".
type Record struct {
	Event     string `json:"event"`
	Agent     string `json:"agent"`
	Inbox     string `json:"inbox,omitempty"` // the inbox the action was scoped to (ADR 0023/0027)
	MessageID string `json:"message_id"`
	Detail    string `json:"detail,omitempty"` // e.g. reject reason, send-attempt result
}

// Entry is a persisted, hash-chained audit entry. Hash binds PrevHash and the
// entry payload, so tampering or truncation within the log breaks the chain
// (ADR 0011).
type Entry struct {
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"` // RFC3339 UTC
	Record   Record `json:"record"`
	PrevHash string `json:"prev_hash"` // hex of the previous entry's hash ("" for the first)
	Hash     string `json:"hash"`      // hex of this entry's hash
}

// AuditLog is a pluggable audit sink. Implementations are selected by config and
// constructed through New.
type AuditLog interface {
	// Append records one entry. For the bbolt log it links into the hash chain.
	Append(Record) error
	// Verify reports the first integrity violation in the log, if any.
	//
	// Integrity is NOT completeness: Verify proves the prev_hash links between
	// the entries that ARE present are intact, but it cannot detect entries that
	// were never written (the best-effort gap, since audit is written after the
	// message-store commit). Detecting such gaps would be a separate
	// message-store-to-audit cross-reference, not Verify's job — see the seam in
	// the bbolt implementation. An empty or disabled log verifies clean.
	Verify() error
	// Close releases the underlying resources.
	Close() error
}

// Factory constructs an AuditLog of a given type from a path (ignored by sinks
// that need no storage, e.g. null).
type Factory func(path string) (AuditLog, error)

var registry = map[string]Factory{}

// Register adds a named audit backend. It panics on a duplicate name (a
// build-wiring error). Backends register from init.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("audit: duplicate registration %q", name))
	}
	registry[name] = f
}

// New constructs the configured audit backend, or an error if auditType is not
// registered.
func New(auditType, path string) (AuditLog, error) {
	f, ok := registry[auditType]
	if !ok {
		return nil, fmt.Errorf("audit: unknown type %q (have %v)", auditType, Registered())
	}
	return f(path)
}

// Registered returns the names of all registered audit backends, sorted.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
