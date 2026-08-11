package listener_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/listener"
)

func TestSingleAuth(t *testing.T) {
	a := listener.SingleAuth("agent", "pw")

	p, ok := a.Verify("agent", "pw")
	assert.True(t, ok)
	assert.Equal(t, "agent", p.Name)

	_, ok = a.Verify("agent", "wrong")
	assert.False(t, ok, "wrong password")

	_, ok = a.Verify("nobody", "pw")
	assert.False(t, ok, "unknown username")
}

// Each agent authenticates with its own credential; one agent's password never
// works for another (ADR 0027 per-agent auth).
func TestAuthPerAgent(t *testing.T) {
	a := listener.NewAuth([]listener.Principal{
		{Name: "agent-a", Password: "pw-a"},
		{Name: "agent-b", Password: "pw-b"},
	})

	p, ok := a.Verify("agent-a", "pw-a")
	assert.True(t, ok)
	assert.Equal(t, "agent-a", p.Name)

	p, ok = a.Verify("agent-b", "pw-b")
	assert.True(t, ok)
	assert.Equal(t, "agent-b", p.Name)

	_, ok = a.Verify("agent-a", "pw-b")
	assert.False(t, ok, "agent-b's password must not authenticate agent-a")

	_, ok = a.Verify("agent-b", "pw-a")
	assert.False(t, ok, "agent-a's password must not authenticate agent-b")
}

// An empty Auth authenticates no one (no panic on the miss path).
func TestAuthEmpty(t *testing.T) {
	a := listener.NewAuth(nil)
	_, ok := a.Verify("agent", "pw")
	assert.False(t, ok)
}

// C31: the credential compare is over fixed-width keyed MACs, so the presented
// password's length is not a branch — a right or wrong password of any length is
// accepted/rejected on its content alone. This is a length-agnostic CORRECTNESS check,
// not a regression guard: a raw byte compare would agree with the MAC compare on every
// non-colliding input, so reverting the fix leaves these assertions green. The timing
// property is not unit-assertable and is verified by review (see Verify).
func TestAuthFixedWidthCompareIsLengthAgnostic(t *testing.T) {
	stored := "pw" // deliberately short, so wrong passwords are both shorter and much longer
	a := listener.NewAuth([]listener.Principal{{Name: "agent", Password: stored}})

	for _, wrong := range []string{"", "x", "pw ", "PW", strings.Repeat("p", 5000)} {
		_, ok := a.Verify("agent", wrong)
		assert.Falsef(t, ok, "wrong password %q (len %d) must be rejected", wrong, len(wrong))
	}
	// The correct password authenticates regardless.
	p, ok := a.Verify("agent", stored)
	assert.True(t, ok)
	assert.Equal(t, "agent", p.Name)

	// Unknown username with a pathological-length password is a clean miss (no panic,
	// same (nil,false) outcome as a wrong password).
	np, ok := a.Verify("nobody", strings.Repeat("z", 5000))
	assert.False(t, ok)
	assert.Nil(t, np)
}
