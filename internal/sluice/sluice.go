// Package sluice is the outbound hold/queue (ADR 0003): the durable store that
// traps every submitted message and holds it under approval. The store is
// abstracted behind the MessageStore interface and selected by config
// (store.type); bbolt is the v1 implementation. The audit log is a separate,
// optional store (see internal/audit) written AFTER each commit — best-effort,
// with this message store as the source of truth.
package sluice

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"sort"
	"time"

	"github.com/emersion/go-message"

	"github.com/yaad-index/darbaan/internal/audit"
)

// ErrNotFound is returned by Get when no message has the given id.
var ErrNotFound = errors.New("sluice: message not found")

// ErrNotPending is returned when a verdict is applied to a message that is no
// longer pending — fail-closed against double decisions.
var ErrNotPending = errors.New("sluice: message is not pending")

// ErrNotApproved is returned by RecordSendAttempt when the message is in a state
// that must never receive a send stamp (pending or rejected). A send is only ever
// recorded against an approved message (or re-recorded against an already-sent one,
// idempotently).
var ErrNotApproved = errors.New("sluice: message is not approved")

// Status is the disposition of a queued message. New messages are Pending; the
// approval pipeline transitions them to Approved or Rejected. Default-deny means
// nothing leaves on Approved either until a real Sender is wired (ADR 0003) —
// Approved records the verdict, it does not imply "sent".
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusSent     Status = "sent" // approved AND delivered upstream
)

// Submission is a new outbound message to trap, as captured from the SMTP face.
type Submission struct {
	Agent string   // authenticated agent identity (ADR 0002)
	Inbox string   // the inbox the From routed to (ADR 0023); "" = default
	From  string   // envelope MAIL FROM
	Rcpt  []string // envelope RCPT TO
	Raw   []byte   // raw message/rfc822
}

// Message is a trapped outbound submission held in the store.
type Message struct {
	ID         string    `json:"id"`
	Agent      string    `json:"agent"`
	Inbox      string    `json:"inbox,omitempty"` // routed inbox (ADR 0023); "" reads as default
	From       string    `json:"from"`
	Rcpt       []string  `json:"rcpt"`
	Raw        []byte    `json:"raw"`
	ReceivedAt time.Time `json:"received_at"`
	Status     Status    `json:"status"`

	// Set on a terminal transition (approved/rejected):
	DecidedBy string `json:"decided_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
	Released  []byte `json:"released,omitempty"` // edited body approved instead of Raw (ADR 0004); nil = original
	SendErr   string `json:"send_err,omitempty"` // result of the last send attempt
}

// Meta is the listing view of a queued message: everything but the raw body.
// Subject is derived from the raw message at list time (not separately stored),
// so admin clients (queue ls, the Telegram bot, a future web UI) get it without
// fetching and re-parsing the body themselves.
type Meta struct {
	ID         string
	Agent      string
	Inbox      string // routed inbox (ADR 0023); "" reads as default
	From       string
	Rcpt       []string
	Subject    string
	Size       int
	ReceivedAt time.Time
	Status     Status
	SendErr    string // the last send attempt's error, so a stranded approved message is visible
}

// subjectFromRaw extracts the Subject header from a stored message for display
// in listings, decoding RFC 2047 encoded-words. Best-effort: a malformed or
// charset-odd message yields "" rather than failing the whole listing.
func subjectFromRaw(raw []byte) string {
	ent, _ := message.Read(bytes.NewReader(raw))
	if ent == nil {
		return "" // unparseable (a charset warning still returns a usable entity)
	}
	s := ent.Header.Get("Subject")
	if dec, err := new(mime.WordDecoder).DecodeHeader(s); err == nil {
		s = dec
	}
	return s
}

// MessageStore is the durable outbound hold/queue. It is the source of truth;
// the audit log it is constructed with is a best-effort record written after
// each commit. Implementations are selected by config (store.type) and
// constructed through New.
type MessageStore interface {
	// Enqueue durably traps a submission as a pending message.
	Enqueue(Submission) (Message, error)
	// List returns the metadata of every held message in receive order.
	List() ([]Meta, error)
	// Get returns the full message (including the raw body), or ErrNotFound.
	Get(id string) (Message, error)
	// Approve marks a pending message approved, recording the deciding approver
	// and (when edited) the released body. It does not send. ErrNotPending if
	// the message is not pending.
	Approve(id, decidedBy string, released []byte) (Message, error)
	// Reject marks a pending message rejected with a reason and retryable flag.
	Reject(id, decidedBy, reason string, retryable bool) (Message, error)
	// RecordSendAttempt records the result of attempting to release an approved
	// message to the upstream Sender.
	RecordSendAttempt(id string, sendErr error) (Message, error)
	// Close releases the underlying resources.
	Close() error
}

// Factory constructs a MessageStore of a given type from a path and the audit
// log it should write to.
type Factory func(path string, log audit.AuditLog) (MessageStore, error)

var registry = map[string]Factory{}

// Register adds a named store backend. It panics on a duplicate name (a
// build-wiring error). Backends register from init.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("sluice: duplicate registration %q", name))
	}
	registry[name] = f
}

// New constructs the configured store backend, or an error if storeType is not
// registered. The store writes best-effort audit entries to log after each
// commit.
func New(storeType, path string, log audit.AuditLog) (MessageStore, error) {
	f, ok := registry[storeType]
	if !ok {
		return nil, fmt.Errorf("sluice: unknown store type %q (have %v)", storeType, Registered())
	}
	return f(path, log)
}

// Registered returns the names of all registered store backends, sorted.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
