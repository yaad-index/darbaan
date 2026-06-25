package approver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/approver"
	"github.com/yaad-index/darbaan/internal/sluice"
)

type fakeApprover struct {
	name    string
	canEdit bool
	verdict approver.Verdict
	err     error
}

func (f fakeApprover) Name() string  { return f.name }
func (f fakeApprover) CanEdit() bool { return f.canEdit }
func (f fakeApprover) Decide(context.Context, sluice.Message) (approver.Verdict, error) {
	return f.verdict, f.err
}

func approve(name string) fakeApprover {
	return fakeApprover{name: name, verdict: approver.Verdict{Disposition: approver.Approve}}
}

var msg = sluice.Message{ID: "1", Raw: []byte("orig")}

func TestRunAllApprove(t *testing.T) {
	out, err := approver.Run(context.Background(), msg, []approver.Approver{approve("a"), approve("b")})
	require.NoError(t, err)
	assert.Equal(t, approver.Approve, out.Disposition)
	assert.Equal(t, []byte("orig"), out.Released)
	assert.Equal(t, "b", out.DecidedBy)
}

func TestRunRejectWinsOverLaterApprove(t *testing.T) {
	// An earlier Reject is the terminal verdict; a later (human) Approve does
	// not override it — every stage must pass (ADR 0004).
	stages := []approver.Approver{
		fakeApprover{name: "screen", verdict: approver.Verdict{Disposition: approver.Reject, Reason: "blocked", Retryable: false}},
		approve("human"),
	}
	out, err := approver.Run(context.Background(), msg, stages)
	require.NoError(t, err)
	assert.Equal(t, approver.Reject, out.Disposition)
	assert.Equal(t, "blocked", out.Reason)
	assert.Equal(t, "screen", out.DecidedBy)
}

func TestRunHoldStaysPending(t *testing.T) {
	// The zero Verdict is Hold ("no decision"), so a stage that returns it keeps
	// the message pending even though an earlier stage approved.
	out, err := approver.Run(context.Background(), msg, []approver.Approver{approve("a"), fakeApprover{name: "h"}})
	require.NoError(t, err)
	assert.Equal(t, approver.Hold, out.Disposition)
}

func TestRunEmptyChainHolds(t *testing.T) {
	out, err := approver.Run(context.Background(), msg, nil)
	require.NoError(t, err)
	assert.Equal(t, approver.Hold, out.Disposition)
}

func TestRunApproverErrorFailsClosed(t *testing.T) {
	stages := []approver.Approver{fakeApprover{name: "boom", err: errors.New("backend down")}}
	out, err := approver.Run(context.Background(), msg, stages)
	require.Error(t, err)
	assert.Equal(t, approver.Hold, out.Disposition)
}

func TestRunEditCapableAmendsReleasedBody(t *testing.T) {
	editor := fakeApprover{
		name:    "human",
		canEdit: true,
		verdict: approver.Verdict{Disposition: approver.Approve, Amended: []byte("edited")},
	}
	out, err := approver.Run(context.Background(), msg, []approver.Approver{editor})
	require.NoError(t, err)
	assert.Equal(t, approver.Approve, out.Disposition)
	assert.Equal(t, []byte("edited"), out.Released)
}

func TestRunEditFromNonEditCapableIsError(t *testing.T) {
	bad := fakeApprover{
		name:    "agent",
		canEdit: false,
		verdict: approver.Verdict{Disposition: approver.Approve, Amended: []byte("sneaky")},
	}
	_, err := approver.Run(context.Background(), msg, []approver.Approver{bad})
	require.Error(t, err)
}
