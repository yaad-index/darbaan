package filter_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
)

// ADR 0022: default_visibility fixes the no-match default AND what a bare
// (action-less) rule does. visible => no-match SHOW, bare match HIDE.
func TestDefaultVisibilityVisible(t *testing.T) {
	f, err := filter.Compile([]byte(`
default_visibility: visible
rules:
  - match: [{field: from, op: domain, value: b.com}]
`))
	require.NoError(t, err)
	now := time.Now()
	// bare rule under visible flips a match to HIDE
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Envelope: from("b.com")}, now))
	// no match => default SHOW
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Envelope: from("other.com")}, now))
	assert.Equal(t, filter.Allow, f.Default())
}

// hidden => no-match HIDE, bare match SHOW (the personal-inbox allowlist).
func TestDefaultVisibilityHidden(t *testing.T) {
	f, err := filter.Compile([]byte(`
default_visibility: hidden
rules:
  - match: [{field: label, op: equals, value: x}]
`))
	require.NoError(t, err)
	now := time.Now()
	// bare rule under hidden flips a match to SHOW
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Keywords: []string{"x"}}, now))
	// no match => default HIDE
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Keywords: []string{"y"}}, now))
	assert.Equal(t, filter.Hide, f.Default())
}

// An explicit action always wins over the mode-implied flip; hold-for-human is
// never implied and stays explicit in either mode.
func TestExplicitActionWinsOverFlip(t *testing.T) {
	f, err := filter.Compile([]byte(`
default_visibility: hidden
rules:
  - match: [{field: label, op: equals, value: review}]
    action: hold-for-human
  - match: [{field: from, op: domain, value: spam.example}]
    action: hide
  - match: [{field: label, op: equals, value: keep}]
`))
	require.NoError(t, err)
	now := time.Now()
	assert.Equal(t, filter.Hold, f.Decide(inbound.Message{Keywords: []string{"review"}}, now))
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Envelope: from("spam.example")}, now))
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Keywords: []string{"keep"}}, now)) // bare => flip to show
}

// Absent key behaves as today (default-allow); legacy default: + explicit
// actions keep working untouched (back-compat is a hard requirement).
func TestBackCompatLegacyDefault(t *testing.T) {
	// absent disposition => visible/default-allow
	f, err := filter.Compile([]byte(`
rules:
  - match: [{field: from, op: domain, value: spam.example}]
    action: hide
`))
	require.NoError(t, err)
	assert.Equal(t, filter.Allow, f.Default())

	// legacy default: hide still honored; a bare rule flips to allow
	g, err := filter.Compile([]byte(`
default: hide
rules:
  - match: [{field: from, op: domain, value: trusted.example}]
`))
	require.NoError(t, err)
	now := time.Now()
	assert.Equal(t, filter.Hide, g.Default())
	assert.Equal(t, filter.Allow, g.Decide(inbound.Message{Envelope: from("trusted.example")}, now))
}

// Synonymous values are accepted; only genuine contradictions are rejected.
func TestDispositionConflicts(t *testing.T) {
	// synonymous: visible + default: allow => OK
	_, err := filter.Compile([]byte("default_visibility: visible\ndefault: allow\nrules: []"))
	assert.NoError(t, err)

	bad := []string{
		"default_visibility: visible\ndefault: hide\nrules: []", // contradiction
		"default_visibility: bogus\nrules: []",                  // unknown disposition
		// a bare rule under legacy default: hold has no disposition to imply an action
		"default: hold-for-human\nrules: [{match: [{field: from, op: equals, value: a@b.com}]}]",
	}
	for _, y := range bad {
		_, err := filter.Compile([]byte(y))
		assert.Error(t, err, y)
	}
}

// Rules() exposes each rule's resolved action + whether it was implied, for the
// `filter explain` dry-run.
func TestRulesViewForExplain(t *testing.T) {
	f, err := filter.Compile([]byte(`
default_visibility: hidden
rules:
  - match: [{field: label, op: equals, value: x}]
  - match: [{field: from, op: domain, value: spam.example}]
    action: hold-for-human
`))
	require.NoError(t, err)
	rules := f.Rules()
	require.Len(t, rules, 2)
	// bare rule: implied flip to allow (under hidden)
	assert.Equal(t, filter.Allow, rules[0].Action)
	assert.True(t, rules[0].Implied)
	assert.Contains(t, rules[0].Match, "label")
	// explicit rule
	assert.Equal(t, filter.Hold, rules[1].Action)
	assert.False(t, rules[1].Implied)
}
