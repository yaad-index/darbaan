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

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/backend"
	"github.com/yaad-index/darbaan/internal/bounce"
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
	store  sluice.MessageStore
	inbox  inbound.InboundStore
	sender backend.Sender
	signer Signer
	router *policy.Router
	domain string
}

// NewService wires the approval service. inbox and signer may be nil only when
// the sender can never permanently fail (the stub) and rejection is unused; in
// serve they are always provided.
func NewService(store sluice.MessageStore, inbox inbound.InboundStore, sender backend.Sender, signer Signer, router *policy.Router, domain string) *Service {
	return &Service{store: store, inbox: inbox, sender: sender, signer: signer, router: router, domain: domain}
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

// ApproveID approves a held message: commit, then send (downstream of commit).
func (s *Service) ApproveID(ctx context.Context, id string) (Outcome, error) {
	m, err := s.decide(ctx, id, approver.Verdict{Disposition: approver.Approve})
	if err != nil {
		return Outcome{}, err
	}
	if m.Status != sluice.StatusApproved {
		return Outcome{ID: m.ID, Status: string(m.Status), Detail: "no verdict applied"}, nil
	}
	out := Outcome{ID: m.ID, Status: string(sluice.StatusApproved), Detail: fmt.Sprintf("approved by %s", m.DecidedBy)}

	sendErr := s.sender.Send(ctx, m)
	final, rerr := s.store.RecordSendAttempt(m.ID, sendErr)
	if rerr != nil {
		return Outcome{}, rerr
	}
	out.Status = string(final.Status)

	switch {
	case sendErr == nil:
		out.Detail = "approved and sent upstream"
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
