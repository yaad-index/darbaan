package filter_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/filter"
	"github.com/yaad-index/darbaan/internal/inbound"
)

func from(host string) *inbound.Envelope {
	return &inbound.Envelope{From: []inbound.Address{{Mailbox: "x", Host: host}}}
}

func TestFilterDecide(t *testing.T) {
	rules := `
default: allow
rules:
  - match:
      - {field: from, op: domain, value: spam.example}
    action: hide
  - match:
      - {field: label, op: equals, value: useless}
    action: hide
  - match:
      - {field: subject, op: contains, value: newsletter}
      - {field: from, op: domain, value: news.example}
    action: hold-for-human
  - match:
      - {field: age, op: older_than, value: 30d}
    action: hide
`
	f, err := filter.Compile([]byte(rules))
	require.NoError(t, err)
	now := time.Now()

	// from-domain → hide
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Envelope: from("spam.example"), ReceivedAt: now}, now))
	// label → hide
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Keywords: []string{"useless"}, ReceivedAt: now}, now))
	// subject AND from → hold (both conditions met)
	assert.Equal(t, filter.Hold, f.Decide(inbound.Message{Subject: "Weekly Newsletter", Envelope: from("news.example"), ReceivedAt: now}, now))
	// subject matches but from-domain doesn't → AND fails → default allow
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Subject: "Weekly Newsletter", Envelope: from("other.example"), ReceivedAt: now}, now))
	// old message → hide (age)
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{ReceivedAt: now.Add(-60 * 24 * time.Hour)}, now))
	// recent, unmatched → default allow
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Subject: "hi", ReceivedAt: now}, now))
}

func TestFilterFirstMatchWins(t *testing.T) {
	f, err := filter.Compile([]byte(`
default: hide
rules:
  - match: [{field: from, op: domain, value: trusted.example}]
    action: allow
  - match: [{field: subject, op: contains, value: x}]
    action: hide
`))
	require.NoError(t, err)
	now := time.Now()
	// first rule (allow) wins even though the second would hide
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Subject: "xx", Envelope: from("trusted.example"), ReceivedAt: now}, now))
	// no rule matches → default hide
	assert.Equal(t, filter.Hide, f.Decide(inbound.Message{Subject: "yy", Envelope: from("other.example"), ReceivedAt: now}, now))
}

func TestFilterNilAndEmptyAllow(t *testing.T) {
	var nilF *filter.Filter
	assert.Equal(t, filter.Allow, nilF.Decide(inbound.Message{}, time.Now()))

	f, err := filter.Load("") // empty path → pass-through
	require.NoError(t, err)
	assert.Equal(t, filter.Allow, f.Decide(inbound.Message{Subject: "anything"}, time.Now()))
}

func TestFilterValidation(t *testing.T) {
	bad := []string{
		"rules: [{match: [{field: from, op: equals, value: a}], action: nope}]",                     // bad action
		"rules: [{match: [{field: nope, op: equals, value: a}], action: hide}]",                     // bad field
		"rules: [{match: [{field: from, op: nope, value: a}], action: hide}]",                       // bad op
		"rules: [{match: [{field: header, header: x-spam, op: contains, value: a}], action: hide}]", // non-envelope header
		"rules: [{match: [{field: subject, op: domain, value: a}], action: hide}]",                  // domain on non-address
		"rules: [{match: [{field: subject, op: regex, value: \"(\"}], action: hide}]",               // bad regex
		"rules: [{match: [{field: age, op: equals, value: 30d}], action: hide}]",                    // bad age op
		"rules: [{match: [], action: hide}]",                                                        // no conditions
		"default: bogus",                                                                            // bad default
	}
	for _, y := range bad {
		_, err := filter.Compile([]byte(y))
		assert.Error(t, err, y)
	}
}
