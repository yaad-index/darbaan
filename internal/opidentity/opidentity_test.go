package opidentity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/opidentity"
)

func mustList(t *testing.T, entries ...string) opidentity.List {
	t.Helper()
	l, err := opidentity.New(entries)
	require.NoError(t, err)
	return l
}

// ADR 0034 condition 4: absent or empty means today's behaviour — everything held.
func TestDisabledByDefault(t *testing.T) {
	for name, l := range map[string]opidentity.List{
		"zero value":  {},
		"empty slice": mustList(t),
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, l.Enabled())
			assert.Equal(t, 0, l.Len())
			_, ok := l.Match("op@example.test")
			assert.False(t, ok, "a disabled list matches nothing")
			_, all := l.AllMatch([]string{"op@example.test"})
			assert.False(t, all, "a disabled list never bypasses")
		})
	}
}

// Parse: the config section is optional, and an absent one is not an error.
func TestParseSection(t *testing.T) {
	t.Run("absent section", func(t *testing.T) {
		l, err := opidentity.Parse([]byte("store:\n  type: bbolt\n"))
		require.NoError(t, err)
		assert.False(t, l.Enabled())
	})
	t.Run("present section", func(t *testing.T) {
		l, err := opidentity.Parse([]byte("operator_identities:\n  - op@example.test\n  - Other Name <two@example.test>\n"))
		require.NoError(t, err)
		require.True(t, l.Enabled())
		assert.Equal(t, 2, l.Len())
		_, ok := l.Match("two@example.test")
		assert.True(t, ok, "a configured entry's display name is discarded, so the bare address matches")
	})
	t.Run("malformed yaml", func(t *testing.T) {
		_, err := opidentity.Parse([]byte("operator_identities: [unclosed\n"))
		require.Error(t, err)
	})
}

// An entry that could never match fails startup rather than loading silently: under
// exact matching it would report the feature's absence as its presence.
func TestEntryThatCanNeverMatchFailsStartup(t *testing.T) {
	for name, entry := range map[string]string{
		// "*" is a legal RFC 5322 atom character, so mail.ParseAddress ACCEPTS
		// "*@example.test" — a parse check alone would let this through.
		"wildcard local part": "*@example.test",
		"wildcard domain":     "op@*.example.test",
		"bare domain":         "@example.test",
		"no domain":           "op",
		"empty":               "",
		"whitespace only":     "   ",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := opidentity.New([]string{entry})
			require.Error(t, err, "entry %q can never match, so it must fail startup", entry)
			assert.Contains(t, err.Error(), "operator_identities[0]", "the error names which entry")
		})
	}
}

// Condition 1: match on the address only, exact — no display name, no domain
// matching, no wildcard, no substring.
func TestMatchIsExactOnTheAddress(t *testing.T) {
	l := mustList(t, "op@example.test")

	t.Run("matches", func(t *testing.T) {
		for _, in := range []string{
			"op@example.test",
			"Some Name <op@example.test>",
			"<op@example.test>",
			"  op@example.test  ",
			"OP@EXAMPLE.TEST", // NormalizeAddress lower-cases, as on the From path
		} {
			got, ok := l.Match(in)
			assert.True(t, ok, "%q should match", in)
			assert.Equal(t, "op@example.test", got, "match returns the canonical address")
		}
	})

	t.Run("does not match", func(t *testing.T) {
		for _, in := range []string{
			"other@example.test",        // different local part
			"op@other.test",             // different domain
			"op@sub.example.test",       // no domain/subdomain matching
			"notop@example.test",        // not a substring match
			"op@example.test.evil.test", // suffix attack
			"op@example",                // truncated domain
			"",
			"not an address",
		} {
			_, ok := l.Match(in)
			assert.False(t, ok, "%q must NOT match", in)
		}
	})
}

// Condition 2: EVERY recipient must be an operator identity, across To/CC/BCC
// alike — one non-matching address sends the whole message down the normal path.
func TestAllMatchRequiresEveryRecipient(t *testing.T) {
	l := mustList(t, "op@example.test", "op2@example.test")

	t.Run("every recipient matches", func(t *testing.T) {
		matched, ok := l.AllMatch([]string{"op@example.test", "Op2 <OP2@example.test>"})
		require.True(t, ok)
		assert.Equal(t, []string{"op@example.test", "op2@example.test"}, matched,
			"matched identities come back canonical, in recipient order")
	})

	t.Run("one stranger disqualifies the whole message", func(t *testing.T) {
		for name, rcpts := range map[string][]string{
			"stranger last":  {"op@example.test", "stranger@elsewhere.test"},
			"stranger first": {"stranger@elsewhere.test", "op@example.test"},
			"stranger only":  {"stranger@elsewhere.test"},
		} {
			t.Run(name, func(t *testing.T) {
				matched, ok := l.AllMatch(rcpts)
				assert.False(t, ok)
				assert.Nil(t, matched, "no partial match is reported, so no caller can send a subset")
			})
		}
	})
}

// 🚨 The vacuity guard. "Every recipient is an operator identity" is vacuously TRUE
// of no recipients, so a naive all-quantifier bypasses a message addressed to
// nobody — a bypass arriving through a condition that reads as a restriction.
func TestZeroRecipientsIsNeverABypass(t *testing.T) {
	l := mustList(t, "op@example.test")
	require.True(t, l.Enabled(), "the control: this list DOES bypass when a recipient matches")
	_, ok := l.AllMatch([]string{"op@example.test"})
	require.True(t, ok, "control failed — the negative below would be vacuous")

	for name, rcpts := range map[string][]string{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			matched, ok := l.AllMatch(rcpts)
			assert.False(t, ok, "no recipients must never bypass")
			assert.Nil(t, matched)
		})
	}
}

// Duplicate entries collapse rather than erroring: two spellings of one address
// are a redundant config, not a broken one.
func TestDuplicateEntriesCollapse(t *testing.T) {
	l := mustList(t, "op@example.test", "OP@example.test", "Op <op@example.test>")
	assert.Equal(t, 1, l.Len())
	_, ok := l.Match("op@example.test")
	assert.True(t, ok)
}
