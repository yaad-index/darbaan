// Package approver decides a held message's fate (ADR 0004, 0005). It defines
// the Approver contract, a registry for compile-time selection (blank-import +
// build-tag pattern), and the fail-closed chain runner. It contains no I/O:
// applying an outcome to the sluice and attempting the send live in the caller.
package approver

import (
	"context"
	"fmt"

	"github.com/yaad-index/darbaan/internal/sluice"
)

// Disposition is the kind of decision an approver returns. The zero value is
// Hold ("no decision"), so an unset or absent verdict keeps a message pending —
// fail-closed by construction (ADR 0003).
type Disposition int

const (
	Hold Disposition = iota // no decision — message stays pending
	Approve
	Reject
)

func (d Disposition) String() string {
	switch d {
	case Approve:
		return "approve"
	case Reject:
		return "reject"
	default:
		return "hold"
	}
}

// Verdict is one approver's decision about a message.
type Verdict struct {
	Disposition Disposition
	Reason      string // required for Reject; the rejection reason (never echoes attacker text, ADR 0006)
	Retryable   bool   // Reject only: transient (revise+resubmit) vs permanent (drop)
	// Amended, when non-nil on an Approve, is an edited body an edit-capable
	// (human) approver chose to release instead of the original (ADR 0004).
	// Agent approvers never set this.
	Amended []byte
}

// Approver decides a pending message's fate. Implementations register for
// compile-time selection via build tags.
type Approver interface {
	// Name identifies the approver in config and the audit trail.
	Name() string
	// CanEdit reports whether this approver may return an amended body. Editing
	// is human-only; agent approvers return false (ADR 0004).
	CanEdit() bool
	// Decide returns a Verdict for msg. The zero Verdict (Hold) means "no
	// decision" and leaves the message pending.
	Decide(ctx context.Context, msg sluice.Message) (Verdict, error)
}

// HumanApprover is an Approver whose verdict is supplied externally (a person
// acting through a surface such as the CLI) rather than computed from the
// message. The caller sets the verdict before running the chain. This keeps the
// human a single stage in the chain — never an override of other stages.
type HumanApprover interface {
	Approver
	SetVerdict(Verdict)
}

// Outcome is the result of running an approval chain over a message.
type Outcome struct {
	Disposition Disposition
	Reason      string
	Retryable   bool
	Released    []byte // body to release on Approve: the original, or an edited version
	DecidedBy   string // the approver that produced the terminal disposition
}

// Run evaluates the stages in order and enforces "every stage must pass"
// (ADR 0004): the message is approved only if every stage approves. The first
// stage to Reject rejects the message; any Hold or approver error leaves it
// pending — fail-closed (ADR 0003). A human Approve does not override an earlier
// stage's Reject, because the first non-approve disposition wins. An
// edit-capable stage may amend the body that later stages see and that is
// ultimately released.
//
// Run makes no decision of its own when the chain is empty: no configured
// approval path means nothing can ever pass, so it Holds.
func Run(ctx context.Context, msg sluice.Message, stages []Approver) (Outcome, error) {
	if len(stages) == 0 {
		return Outcome{Disposition: Hold}, nil
	}

	released := msg.Raw
	working := msg
	for _, st := range stages {
		v, err := st.Decide(ctx, working)
		if err != nil {
			// Fail-closed: an approver error never approves.
			return Outcome{Disposition: Hold, DecidedBy: st.Name()},
				fmt.Errorf("approver %q: %w", st.Name(), err)
		}
		switch v.Disposition {
		case Reject:
			return Outcome{
				Disposition: Reject,
				Reason:      v.Reason,
				Retryable:   v.Retryable,
				DecidedBy:   st.Name(),
			}, nil
		case Hold:
			return Outcome{Disposition: Hold, DecidedBy: st.Name()}, nil
		case Approve:
			if v.Amended != nil {
				if !st.CanEdit() {
					return Outcome{}, fmt.Errorf("approver %q returned an edit but is not edit-capable", st.Name())
				}
				released = v.Amended
				working.Raw = v.Amended
			}
		default:
			return Outcome{}, fmt.Errorf("approver %q returned unknown disposition %d", st.Name(), v.Disposition)
		}
	}

	return Outcome{
		Disposition: Approve,
		Released:    released,
		DecidedBy:   stages[len(stages)-1].Name(),
	}, nil
}
