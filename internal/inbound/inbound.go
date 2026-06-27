// Package inbound is the agent's served mailbox: the store of messages Darbaan
// delivers TO the agent — v1 holds MAILER-DAEMON bounces (ADR 0006), which the
// IMAP face serves (#27). It is deliberately separate from the sluice: a bounce
// is a message the agent reads, never an outbound submission awaiting approval.
// The store is abstracted behind InboundStore and selected by config
// (inbound-type); bbolt is the v1 implementation.
package inbound

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrNotFound is returned by Get when no message matches.
var ErrNotFound = errors.New("inbound: message not found")

// Delivery is a new inbound message to store.
type Delivery struct {
	Owner   string // the agent whose mailbox this is (whose send was rejected)
	From    string // e.g. MAILER-DAEMON@<domain>
	To      string // the original submitter
	Subject string
	Raw     []byte // full message/rfc822 (the DSN bounce)

	// Upstream coordinates for messages pulled by the inbound sync (ADR 0019);
	// zero for locally-generated deliveries like bounces. AddSynced uses them to
	// dedup an idempotent re-sync and (later) to fetch content on demand.
	UpstreamUID uint32
	UIDValidity uint32
}

// Message is a stored inbound message.
type Message struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Subject    string    `json:"subject"`
	Raw        []byte    `json:"raw"`
	Seen       bool      `json:"seen"` // IMAP \Seen; bounces land unseen
	ReceivedAt time.Time `json:"received_at"`

	// Upstream coordinates (ADR 0019); zero for locally-generated messages.
	UpstreamUID uint32 `json:"upstream_uid,omitempty"`
	UIDValidity uint32 `json:"uid_validity,omitempty"`
}

// InboundStore is the agent's served mailbox. Implementations are selected by
// config (inbound-type) and constructed through New.
type InboundStore interface {
	// Add stores a delivery and returns the stored message.
	Add(Delivery) (Message, error)
	// AddSynced stores a message pulled from upstream, keyed for idempotency by
	// its upstream (UIDValidity, UpstreamUID). If that upstream message is
	// already stored it is a no-op returning added=false; otherwise it is stored
	// and added=true. The Delivery must carry non-zero upstream coordinates.
	AddSynced(Delivery) (added bool, m Message, err error)
	// List returns the owner's messages in receive order.
	List(owner string) ([]Message, error)
	// Get returns one of the owner's messages, or ErrNotFound.
	Get(owner, id string) (Message, error)
	// SetSeen sets or clears the \Seen flag on the owner's message — the only
	// mutable flag the v1 IMAP face persists. Owner-scoped like Get.
	SetSeen(owner, id string, seen bool) error
	// Close releases the underlying resources.
	Close() error
}

// Factory constructs an InboundStore of a given type from a path.
type Factory func(path string) (InboundStore, error)

var registry = map[string]Factory{}

// Register adds a named inbound backend. It panics on a duplicate name.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("inbound: duplicate registration %q", name))
	}
	registry[name] = f
}

// New constructs the configured inbound backend, or an error if inboundType is
// not registered.
func New(inboundType, path string) (InboundStore, error) {
	f, ok := registry[inboundType]
	if !ok {
		return nil, fmt.Errorf("inbound: unknown type %q (have %v)", inboundType, Registered())
	}
	return f(path)
}

// Registered returns the names of all registered inbound backends, sorted.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
