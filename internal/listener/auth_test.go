package listener_test

import (
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
