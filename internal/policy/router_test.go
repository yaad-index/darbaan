package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yaad-index/darbaan/internal/policy"
)

func TestRouterNilRiskIsStrict(t *testing.T) {
	r := policy.NewRouter([]string{"manual"}, []string{"light-only"})
	chain, names := r.Select(nil)
	assert.Equal(t, policy.StrictChain, chain)
	assert.Equal(t, []string{"manual"}, names)
}

func TestRouterLowNoFlagsIsLight(t *testing.T) {
	r := policy.NewRouter([]string{"manual"}, []string{"light-only"})
	chain, names := r.Select(&policy.Risk{Level: "low"})
	assert.Equal(t, policy.LightChain, chain)
	assert.Equal(t, []string{"light-only"}, names)
}

func TestRouterLowWithFlagIsStrict(t *testing.T) {
	r := policy.NewRouter([]string{"manual"}, []string{"light-only"})
	chain, _ := r.Select(&policy.Risk{Level: "low", Flags: []string{"touches-secret"}})
	assert.Equal(t, policy.StrictChain, chain)
}

func TestRouterElevatedRiskIsStrict(t *testing.T) {
	r := policy.NewRouter([]string{"manual"}, []string{"light-only"})
	for _, lvl := range []string{"medium", "high"} {
		chain, _ := r.Select(&policy.Risk{Level: lvl})
		assert.Equal(t, policy.StrictChain, chain, "level %s", lvl)
	}
}
