// Package admin is the operator's approval surface for a running serve process.
// Because bbolt is single-writer, the serve process owns the stores and exposes
// list/show/approve/reject over a localhost-only HTTP API (see http.go); the
// `darbaan queue` CLI is a thin client (client.go). The approval chain, the
// upstream send, and bounce delivery all run here, in serve — so default-deny
// and fail-closed are unchanged (ADR 0003); the surface is reachable only by the
// operator, never the agent (ADR 0002).
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/bounce"
	"github.com/yaad-index/darbaan/internal/bounceguard"
	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
	"github.com/yaad-index/darbaan/internal/policy"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Signer signs a bounce before it is stored. *signer.Signer implements it.
type Signer interface {
	Sign(raw []byte) ([]byte, error)
}

// Service runs the approval orchestration against the stores serve owns.
type Service struct {
	store      sluice.MessageStore
	inbox      inbound.InboundStore
	senders    map[string]backend.Sender // per-inbox upstream sender (ADR 0023), keyed by inbox name
	identities map[string]string         // per-inbox send identity (ADR 0023 slice 5), keyed by inbox name; for ApproveAs
	signer     Signer
	router     *policy.Router
	domain     string
	filters    map[string]*filter.Filter // per-inbox filter for the hold-for-human queue (ADR 0021/0023)
	owner      string                    // the agent whose inbound mailbox the holds belong to
	guard      *bounceguard.Guard        // inbound bounce-spoof guard (ADR 0024; nil = off)
	holdSpoof  bool                      // on_spoof=hold-for-human → spoofs join the held queue

	// Reconcile controls (ADR 0026), wired by serve over its per-inbox syncers;
	// nil when no inbox has an upstream (nothing to reconcile).
	reconcileRelease func(ctx context.Context, inbox string) (int, error)
	reconcileStatus  func() ([]ReconcileStatus, error)
}

// ReconcileStatus reports one inbox's reconciliation latch (ADR 0026): whether
// the safety cap has it suspended, and the candidate count that tripped it.
type ReconcileStatus struct {
	Inbox     string `json:"inbox"`
	Suspended bool   `json:"suspended"`
	HeldCount int    `json:"held_count"`
}

// ReconcileReleaseResult is the outcome of releasing a latched inbox (ADR 0026).
type ReconcileReleaseResult struct {
	Inbox  string `json:"inbox"`
	Purged int    `json:"purged"`
}

// ErrReconcileUnavailable is returned by the reconcile controls when no inbox has
// an upstream syncer, so there is nothing to reconcile or release.
var ErrReconcileUnavailable = errors.New("admin: reconcile control not available (no upstream inbox configured)")

// ErrReconcileNotHeld is returned by ReleaseReconcile when the inbox is not held
// by the safety cap — there is nothing to release. serve translates the syncer's
// equivalent error into this so the API can answer 409 (conflict) rather than 500.
var ErrReconcileNotHeld = errors.New("admin: inbox is not held by the reconcile safety cap (nothing to release)")

// SetReconcileControls wires the reconcile release/status callbacks (ADR 0026).
// serve supplies them over its per-inbox syncers; without them the endpoints
// report ErrReconcileUnavailable.
func (s *Service) SetReconcileControls(release func(context.Context, string) (int, error), status func() ([]ReconcileStatus, error)) {
	s.reconcileRelease = release
	s.reconcileStatus = status
}

// ReleaseReconcile releases a latched inbox (ADR 0026): the operator confirms the
// large retraction is legitimate; the held purge completes once and capped
// reconciliation resumes. Returns the number retracted.
func (s *Service) ReleaseReconcile(ctx context.Context, inbox string) (int, error) {
	if s.reconcileRelease == nil {
		return 0, ErrReconcileUnavailable
	}
	return s.reconcileRelease(ctx, inbox)
}

// ReconcileStatusAll lists every inbox's reconciliation latch (ADR 0026) so the
// operator can discover which inboxes are held.
func (s *Service) ReconcileStatusAll() ([]ReconcileStatus, error) {
	if s.reconcileStatus == nil {
		return nil, ErrReconcileUnavailable
	}
	return s.reconcileStatus()
}

// NewService wires the approval service. inbox and signer may be nil only when
// the sender can never permanently fail (the stub) and rejection is unused; in
// serve they are always provided.
func NewService(store sluice.MessageStore, inbox inbound.InboundStore, sender backend.Sender, signer Signer, router *policy.Router, domain string) *Service {
	// The single sender becomes the default inbox's; SetSenders installs the
	// per-inbox map in serve (ADR 0023). Keeps existing callers/tests unchanged.
	return &Service{store: store, inbox: inbox, senders: map[string]backend.Sender{inbound.DefaultInbox: sender}, signer: signer, router: router, domain: domain}
}

// SetSenders installs the per-inbox upstream senders (ADR 0023): an approved
// message is delivered via the sender of the inbox it was submitted as. serve
// builds one per configured inbox; tests/callers that only need one inbox keep
// using NewService's single sender.
func (s *Service) SetSenders(senders map[string]backend.Sender) {
	if len(senders) > 0 {
		s.senders = senders
	}
}

// senderFor returns the upstream sender for a message's inbox, falling back to the
// default inbox's sender when the message carries no/unknown inbox (ADR 0023).
func (s *Service) senderFor(inbox string) backend.Sender {
	if snd := s.senders[inbound.NormInbox(inbox)]; snd != nil {
		return snd
	}
	return s.senders[inbound.DefaultInbox]
}

// SetInboundHolds wires the inbound hold-for-human queue (ADR 0021/0023): the
// per-inbox filters that decide which synced messages are held, the agent (owner)
// they belong to, and the bounce-spoof guard (ADR 0024). When the guard is set
// with holdSpoof, spoof candidates also join the held queue. Without filters,
// HeldList is empty.
func (s *Service) SetInboundHolds(filters map[string]*filter.Filter, owner string, guard *bounceguard.Guard, holdSpoof bool) {
	s.filters, s.owner, s.guard, s.holdSpoof = filters, owner, guard, holdSpoof
}

// HeldList returns the inbound messages held for a human decision with no
// decision yet — a hold-rule match (ADR 0021) or, under on_spoof=hold-for-human,
// a bounce-spoof candidate (ADR 0024) — aggregated across every inbox (ADR 0023),
// each evaluated by its own filter. The inbound mirror of the outbound List.
func (s *Service) HeldList() ([]inbound.Message, error) {
	if s.inbox == nil {
		return nil, nil
	}
	now := time.Now()
	var held []inbound.Message
	for _, inbox := range s.inboxNames() {
		msgs, err := s.inbox.List(s.owner, inbox)
		if err != nil {
			return nil, err
		}
		flt := s.filters[inbox]
		for _, m := range msgs {
			if m.HoldDecision != "" {
				continue // already decided
			}
			if (flt != nil && flt.Decide(m, now) == filter.Hold) || s.guardHoldsSpoof(m, inbox) {
				held = append(held, m)
			}
		}
	}
	return held, nil
}

// inboxNames returns the configured inbox names in stable order (the held queue is
// aggregated deterministically across inboxes).
func (s *Service) inboxNames() []string {
	names := make([]string, 0, len(s.filters))
	for inbox := range s.filters {
		names = append(names, inbox)
	}
	sort.Strings(names)
	return names
}

// guardHoldsSpoof reports whether m (in the given inbox) is a bounce-spoof
// candidate routed to the held queue (on_spoof=hold-for-human, ADR 0024). False
// when the guard is off or on_spoof=hide (hidden spoofs aren't a human-decision
// queue item).
func (s *Service) guardHoldsSpoof(m inbound.Message, inbox string) bool {
	if s.guard == nil || !s.holdSpoof {
		return false
	}
	// Verdict is fail-CLOSED for a candidate it can't fetch/verify (ADR 0024), so
	// a spoof the read face hides is also surfaced here for an operator decision —
	// the two stay consistent. The error rides along with spoof=true; the read
	// face logs it.
	spoof, _ := s.guard.Verdict(envelopeFromLocals(m), m.Raw, func() ([]byte, error) {
		fm, e := s.inbox.Get(s.owner, inbox, m.ID)
		return fm.Raw, e
	})
	return spoof
}

// envelopeFromLocals returns the local-parts of a message's envelope From
// addresses — the metadata-cheap input to the guard's From-precheck (ADR 0024).
func envelopeFromLocals(m inbound.Message) []string {
	if m.Envelope == nil {
		return nil
	}
	out := make([]string, 0, len(m.Envelope.From))
	for _, a := range m.Envelope.From {
		out = append(out, a.Mailbox)
	}
	return out
}

// ExposeHeld approves a held message for the agent to see (ADR 0021).
func (s *Service) ExposeHeld(id string) (inbound.Message, error) {
	return s.setHold(id, inbound.HoldApproved)
}

// DropHeld rejects a held message — it stays hidden from the agent (ADR 0021).
func (s *Service) DropHeld(id string) (inbound.Message, error) {
	return s.setHold(id, inbound.HoldRejected)
}

// setHold applies a hold decision to the message with this (store-wide unique) id,
// resolving which inbox holds it (ADR 0023): the id is unique across the store, so
// at most one inbox's (owner,inbox)-scoped record matches and the rest return
// ErrNotFound. Returns ErrNotFound if no inbox holds it.
func (s *Service) setHold(id, decision string) (inbound.Message, error) {
	for _, inbox := range s.inboxNames() {
		m, err := s.inbox.SetHoldDecision(s.owner, inbox, id, decision)
		if err == nil {
			return m, nil
		}
		if !errors.Is(err, inbound.ErrNotFound) {
			return inbound.Message{}, err
		}
	}
	return inbound.Message{}, inbound.ErrNotFound
}

// Outcome is the result of an approve/reject action. Status is the committed
// state (the source of truth); Warn carries a non-fatal downstream issue (a send
// or bounce-delivery failure) without claiming the verdict itself failed.
type Outcome struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Warn   string `json:"warn,omitempty"`
}

// List returns the held messages' metadata.
func (s *Service) List() ([]sluice.Meta, error) { return s.store.List() }

// Show returns the full message (raw body included).
func (s *Service) Show(id string) (sluice.Message, error) { return s.store.Get(id) }

// decide runs the approval chain for one message and commits the outcome —
// nothing more (pure). Everything downstream lives in Approve/Reject.
func (s *Service) decide(ctx context.Context, id string, human approver.Verdict) (sluice.Message, error) {
	msg, err := s.store.Get(id)
	if err != nil {
		return sluice.Message{}, err
	}
	if msg.Status != sluice.StatusPending {
		return sluice.Message{}, fmt.Errorf("%w: message %s is %s", sluice.ErrNotPending, id, msg.Status)
	}

	// No pre-screener exists, so the router runs with no risk signal and returns
	// the strict chain (the ADR 0005 fail-safe).
	_, names := s.router.Select(nil)
	stages := make([]approver.Approver, 0, len(names))
	for _, name := range names {
		a, err := approver.New(name)
		if err != nil {
			return sluice.Message{}, err
		}
		if h, ok := a.(approver.HumanApprover); ok {
			h.SetVerdict(human)
		}
		stages = append(stages, a)
	}

	outcome, err := approver.Run(ctx, msg, stages)
	if err != nil {
		return sluice.Message{}, err
	}
	switch outcome.Disposition {
	case approver.Approve:
		return s.store.Approve(id, outcome.DecidedBy, outcome.Released)
	case approver.Reject:
		return s.store.Reject(id, outcome.DecidedBy, outcome.Reason, outcome.Retryable)
	default:
		return msg, nil // Hold — stays pending
	}
}

// ApproveID approves a held message and sends it as submitted, via its stamped
// inbox's sender (ADR 0023). ApproveAs sends it from a chosen inbox's identity.
func (s *Service) ApproveID(ctx context.Context, id string) (Outcome, error) {
	return s.approve(ctx, id, "")
}

// ApproveAs approves a held message and sends it from asInbox's identity (ADR
// 0023 slice 5, #139): the envelope MAIL FROM and the From header are rewritten
// to that inbox's identity and the send is routed through that inbox's Sender.
// asInbox must be a configured inbox that has an identity. The persisted record
// keeps the message as submitted (send-time rewrite only); the chosen identity is
// recorded in a structured log event.
func (s *Service) ApproveAs(ctx context.Context, id, asInbox string) (Outcome, error) {
	return s.approve(ctx, id, asInbox)
}

// approve commits the approve verdict, then sends downstream of the commit. When
// asInbox is empty the message is sent as-stamped via its own inbox's sender;
// otherwise its From (envelope + header) is rewritten to asInbox's identity and
// it is sent via asInbox's sender — the send-time rewrite never mutates the
// stored record.
func (s *Service) approve(ctx context.Context, id, asInbox string) (Outcome, error) {
	m, err := s.decide(ctx, id, approver.Verdict{Disposition: approver.Approve})
	if err != nil {
		return Outcome{}, err
	}
	if m.Status != sluice.StatusApproved {
		return Outcome{ID: m.ID, Status: string(m.Status), Detail: "no verdict applied"}, nil
	}
	out := Outcome{ID: m.ID, Status: string(sluice.StatusApproved), Detail: fmt.Sprintf("approved by %s", m.DecidedBy)}

	sendInbox, sendMsg := m.Inbox, m
	var identity string
	if asInbox != "" {
		identity = s.identities[inbound.NormInbox(asInbox)]
		if identity == "" {
			return Outcome{}, fmt.Errorf("%w: %q", ErrUnknownInbox, asInbox)
		}
		rewritten, rwErr := rewriteFrom(sendBody(m), identity)
		if rwErr != nil {
			return Outcome{}, fmt.Errorf("admin: rewrite From to %q: %w", identity, rwErr)
		}
		sendInbox = asInbox
		sendMsg.From = identity      // envelope MAIL FROM
		sendMsg.Released = rewritten // the sender prefers Released over Raw (send-time only)
		slog.Info("approved-as", "message_id", m.ID, "inbox", inbound.NormInbox(asInbox), "identity", identity)
	}

	sendErr := s.senderFor(sendInbox).Send(ctx, sendMsg)
	final, rerr := s.store.RecordSendAttempt(m.ID, sendErr)
	if rerr != nil {
		return Outcome{}, rerr
	}
	out.Status = string(final.Status)

	sentDetail := "approved and sent upstream"
	if identity != "" {
		sentDetail = "approved and sent upstream as " + identity
	}
	switch {
	case sendErr == nil:
		out.Detail = sentDetail
	case isSendPending(sendErr):
		out.Detail = "approved; no real Sender configured — nothing left Darbaan"
	case backend.IsPermanent(sendErr):
		// Permanent failure: bounce the agent with a generic reason (never the
		// upstream body). The verdict still committed.
		if bErr := s.deliverBounce(m, "upstream delivery failed permanently", false); bErr != nil {
			out.Warn = fmt.Sprintf("send failed permanently AND bounce delivery failed: %v", bErr)
		} else {
			out.Warn = "upstream send failed permanently — bounced to agent"
		}
	default:
		out.Warn = "upstream send failed (transient); stays approved for re-send"
	}
	return out, nil
}

// RejectID rejects a held message: commit, then deliver the DSN bounce
// (downstream of commit, never mistaken for a reject failure, ADR 0006).
func (s *Service) RejectID(ctx context.Context, id, reason string, retryable bool) (Outcome, error) {
	m, err := s.decide(ctx, id, approver.Verdict{Disposition: approver.Reject, Reason: reason, Retryable: retryable})
	if err != nil {
		return Outcome{}, err
	}
	if m.Status != sluice.StatusRejected {
		return Outcome{ID: m.ID, Status: string(m.Status), Detail: "no verdict applied"}, nil
	}
	kind := "permanent"
	if m.Retryable {
		kind = "transient"
	}
	out := Outcome{ID: m.ID, Status: string(sluice.StatusRejected), Detail: fmt.Sprintf("rejected by %s (%s): %s", m.DecidedBy, kind, m.Reason)}

	if bErr := s.deliverBounce(m, m.Reason, m.Retryable); bErr != nil {
		out.Warn = fmt.Sprintf("bounce delivery FAILED (agent not notified, needs redelivery): %v", bErr)
	} else {
		out.Detail += "; bounce delivered"
	}
	return out, nil
}

// deliverBounce generates, signs, and delivers the DSN bounce for an
// already-decided message (ADR 0006). Signing is required (ADR 0007).
func (s *Service) deliverBounce(m sluice.Message, reason string, retryable bool) error {
	if s.inbox == nil || s.signer == nil {
		return fmt.Errorf("bounce path not configured")
	}
	b, err := bounce.Generate(m, reason, retryable, s.domain)
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	signed, err := s.signer.Sign(b.Raw)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if _, err := s.inbox.Add(inbound.Delivery{
		Owner: b.Owner, From: b.From, To: b.To, Subject: b.Subject, Raw: signed,
	}); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func isSendPending(err error) bool {
	return errors.Is(err, backend.ErrSendPending)
}
