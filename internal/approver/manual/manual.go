// Package manual is the v1 human approver: a person decides through a surface
// (the CLI) and the verdict is injected before the chain runs. Web and chat
// approvers come later behind the same Approver contract. Blank-import this
// package to compile it in (ADR 0004).
package manual

import (
	"context"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/sluice"
)

// Name is the registry key for the manual approver.
const Name = "manual"

func init() {
	approver.Register(Name, func() approver.Approver { return &Manual{} })
}

// Manual is a human approver. Its verdict is set externally (SetVerdict) by the
// surface the human acted through; Decide just returns it. The zero value
// returns Hold, so a constructed-but-unset manual approver keeps the message
// pending — fail-closed.
type Manual struct {
	verdict approver.Verdict
}

// New returns a Manual carrying v, for callers that construct it directly.
func New(v approver.Verdict) *Manual { return &Manual{verdict: v} }

// SetVerdict supplies the human's decision before the chain runs.
func (m *Manual) SetVerdict(v approver.Verdict) { m.verdict = v }

// Name identifies the approver.
func (m *Manual) Name() string { return Name }

// CanEdit is true: a human may edit a draft before releasing it (ADR 0004).
func (m *Manual) CanEdit() bool { return true }

// Decide returns the human's verdict, independent of the message contents.
func (m *Manual) Decide(_ context.Context, _ sluice.Message) (approver.Verdict, error) {
	return m.verdict, nil
}
