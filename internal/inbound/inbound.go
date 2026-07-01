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

// Address is one parsed envelope address. It mirrors the IMAP envelope address
// (name + mailbox@host) without importing the IMAP library, keeping the store
// IMAP-type-free (ADR 0016).
type Address struct {
	Name    string `json:"name,omitempty"`
	Mailbox string `json:"mailbox,omitempty"`
	Host    string `json:"host,omitempty"`
}

// Envelope is the parsed message envelope (RFC 3501 §7.4.2), stored as metadata
// so the IMAP read face can serve FETCH ENVELOPE and header SEARCH from the store
// without fetching the body (lazy, ADR 0019). nil for records synced before the
// envelope was stored and for some locally-generated messages — callers fall
// back to parsing the raw for those.
type Envelope struct {
	Date      time.Time `json:"date,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	From      []Address `json:"from,omitempty"`
	Sender    []Address `json:"sender,omitempty"`
	ReplyTo   []Address `json:"reply_to,omitempty"`
	To        []Address `json:"to,omitempty"`
	Cc        []Address `json:"cc,omitempty"`
	Bcc       []Address `json:"bcc,omitempty"`
	InReplyTo []string  `json:"in_reply_to,omitempty"`
	MessageID string    `json:"message_id,omitempty"`
}

// Delivery is a new inbound message to store.
type Delivery struct {
	Owner   string // the agent whose mailbox this is (whose send was rejected)
	Inbox   string // the named inbox this delivery belongs to (ADR 0023); "" = DefaultInbox
	From    string // e.g. MAILER-DAEMON@<domain>
	To      string // the original submitter
	Subject string
	Raw     []byte // full message/rfc822 (the DSN bounce)

	// Upstream coordinates for messages pulled by the inbound sync (ADR 0019);
	// zero for locally-generated deliveries like bounces. AddSynced uses them to
	// dedup an idempotent re-sync and (later) to fetch content on demand.
	UpstreamUID uint32
	UIDValidity uint32

	// Envelope + Size are stored metadata so the IMAP read face serves FETCH
	// ENVELOPE / RFC822Size / header SEARCH without the body (ADR 0019). Envelope
	// is nil and Size 0 for locally-generated deliveries; the read face falls back
	// to the raw for those.
	Envelope *Envelope
	Size     int64

	// Keywords are the message's custom IMAP keywords/labels (ADR 0020), pulled
	// from upstream by the sync; nil for locally-generated deliveries.
	Keywords []string
}

// Message is a stored inbound message.
type Message struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	Inbox      string    `json:"inbox,omitempty"` // named inbox (ADR 0023); "" reads as DefaultInbox
	From       string    `json:"from"`
	To         string    `json:"to"`
	Subject    string    `json:"subject"`
	Raw        []byte    `json:"raw"`
	Seen       bool      `json:"seen"` // IMAP \Seen; bounces land unseen
	ReceivedAt time.Time `json:"received_at"`

	// Upstream coordinates (ADR 0019); zero for locally-generated messages.
	UpstreamUID uint32 `json:"upstream_uid,omitempty"`
	UIDValidity uint32 `json:"uid_validity,omitempty"`

	// Pending means the headers are synced but the body/content has not been
	// fetched yet (lazy sync, ADR 0019). Raw is empty until it is fetched on
	// demand (Syncer.FetchContent → SetContent); callers must not treat a pending
	// message's empty Raw as "no body".
	Pending bool `json:"pending,omitempty"`

	// Envelope + Size are stored metadata for the IMAP read face: FETCH ENVELOPE,
	// RFC822Size, and header SEARCH (Subject/From/To/Date) serve from these
	// without the body. Envelope is nil / Size 0 for records stored before the
	// envelope was captured (pre-#93 syncs, bounces); the read face then derives
	// from the raw.
	Envelope *Envelope `json:"envelope,omitempty"`
	Size     int64     `json:"size,omitempty"`

	// Keywords are the message's custom IMAP keywords/labels (ADR 0020), served
	// on FETCH FLAGS. The agent sets them via STORE (write-through to upstream).
	Keywords []string `json:"keywords,omitempty"`

	// HoldDecision records the human's call on a hold-for-human message (ADR
	// 0021): "" = undecided (held, hidden from the agent), "approved" = exposed to
	// the agent, "rejected" = stays hidden. Only meaningful while a hold rule
	// matches the message; it is the one persisted, human-supplied filter state.
	HoldDecision string `json:"hold_decision,omitempty"`
}

// Hold decision values for Message.HoldDecision (ADR 0021).
const (
	HoldApproved = "approved"
	HoldRejected = "rejected"
)

// DefaultInbox is the implicit single inbox (ADR 0023). A record stored before
// multi-inbox carries no Inbox and reads as DefaultInbox, and a single-inbox
// deployment addresses everything as DefaultInbox — so N=1 is unchanged.
const DefaultInbox = "default"

// NormInbox resolves an empty inbox name to DefaultInbox, so stored records
// written before multi-inbox (Inbox == "") match the default inbox.
func NormInbox(inbox string) string {
	if inbox == "" {
		return DefaultInbox
	}
	return inbox
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
	// AddSyncedPending stores a headers-only (Pending) record — metadata without
	// content — for lazy sync (ADR 0019). Same idempotency as AddSynced; the
	// Delivery's Raw is ignored. SetContent fills the body later.
	AddSyncedPending(Delivery) (added bool, m Message, err error)
	// SetContent fills a pending message's body (write the content blob, mark it
	// present) and returns the now-complete message. Scoped to (owner, inbox).
	SetContent(owner, inbox, id string, raw []byte) (Message, error)
	// SetKeywords replaces a message's keyword set (ADR 0020) and marks it dirty
	// for upstream reconcile. Local store is canonical. Scoped to (owner, inbox).
	SetKeywords(owner, inbox, id string, keywords []string) (Message, error)
	// ClearKeywordsDirty clears the dirty flag after upstream replication succeeds.
	ClearKeywordsDirty(owner, inbox, id string) error
	// DirtyKeywords returns the inbox's messages whose keywords await upstream
	// replication — per inbox, since each inbox reconciles against its own backend.
	DirtyKeywords(owner, inbox string) ([]Message, error)
	// SetHoldDecision persists the human's hold-for-human decision (ADR 0021):
	// "approved" exposes the message, "rejected" keeps it hidden. (owner, inbox)-scoped.
	SetHoldDecision(owner, inbox, id, decision string) (Message, error)
	// List returns the inbox's messages' metadata (no content/Raw) in receive
	// order; a body is fetched per-message via Get / the content fetcher. Each
	// inbox is an independent mailbox (ADR 0023).
	List(owner, inbox string) ([]Message, error)
	// Get returns one of the inbox's messages with content, or ErrNotFound.
	Get(owner, inbox, id string) (Message, error)
	// SetSeen sets or clears the \Seen flag on the inbox's message — the only
	// mutable flag the v1 IMAP face persists. (owner, inbox)-scoped like Get.
	SetSeen(owner, inbox, id string, seen bool) error
	// RemoveSynced hard-removes an upstream-synced message — its metadata record,
	// dedup-index entry, and content blob — so it disappears from the read face
	// entirely. This is the retraction path for upstream reconciliation (ADR 0026):
	// the source dropped the message, so Darbaan drops its local copy (the upstream
	// itself is never touched). It is (owner, inbox)-scoped like Get and **refuses a
	// locally-generated record** (UpstreamUID == 0, e.g. a signed bounce) — those
	// have no upstream and are never reconciled. Returns ErrNotFound if the
	// (owner, inbox) has no such message.
	RemoveSynced(owner, inbox, id string) error
	// RekeyOwnersToInbox rewrites every synced record's owner key to its inbox name
	// (ADR 0027 mail-owner decoupling), so several agents sharing an inbox key into
	// the same records. Locally-generated records (UpstreamUID == 0, e.g. bounces)
	// keep their originating-agent owner and are never rekeyed — a bounce stays
	// private to its originator. It is idempotent (a record already inbox-owned is
	// skipped) and returns the number of records rewritten. Multi-agent deployments
	// run it once at startup; the single-agent path never calls it.
	RekeyOwnersToInbox() (int, error)
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
