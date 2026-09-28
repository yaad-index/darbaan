package inboxcfg

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const knownInbox = `
inboxes:
  - name: work
    identity: me@x.test
    trust:
      level: trusted
      note: "operator mail"
      rules:
        - from: a@x.test
          level: untrusted
`

func TestUnknownKeysNoneForKnownSettings(t *testing.T) {
	got, err := UnknownKeys([]byte(knownInbox))
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = UnknownKeys([]byte("admin-addr: x\n"))
	require.NoError(t, err)
	assert.Nil(t, got, "no inboxes: section, nothing to report")
}

// A key that matches no setting is reported with its full path, at any depth.
func TestUnknownKeysNamesEveryIgnoredKey(t *testing.T) {
	y := strings.Replace(knownInbox, "    identity: me@x.test\n", "    identityy: me@x.test\n", 1)
	y = strings.Replace(y, "          level: untrusted\n", "          levelx: untrusted\n", 1)
	got, err := UnknownKeys([]byte(y))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"inboxes[0].identityy", "inboxes[0].trust.rules[0].levelx"}, got)
}

// #237 A1: the gate's settings are real settings of an inbox's trust block, so
// they are not reported as ignored there.
func TestGateSettingsAreKnownUnderTrust(t *testing.T) {
	y := strings.Replace(knownInbox, "      level: trusted\n",
		"      level: trusted\n      require_authenticated: true\n      authserv_id: mx.example\n", 1)
	got, err := UnknownKeys([]byte(y))
	require.NoError(t, err)
	assert.Empty(t, got)
	ins, err := Parse([]byte(y))
	require.NoError(t, err)
	require.Len(t, ins, 1)
	assert.True(t, ins[0].Trust.RequireAuthenticated)
	assert.Equal(t, "mx.example", ins[0].Trust.AuthservID)
}

// Only under trust: the same name elsewhere is an ordinary unknown key (logged,
// not fatal), so the check cannot fire on an unrelated setting.
func TestParseRejectsGateSettingsOnlyUnderTrust(t *testing.T) {
	y := strings.Replace(knownInbox, "    identity: me@x.test\n", "    identity: me@x.test\n    authserv_id: x\n", 1)
	_, err := Parse([]byte(y))
	require.NoError(t, err)
	got, err := UnknownKeys([]byte(y))
	require.NoError(t, err)
	assert.Equal(t, []string{"inboxes[0].authserv_id"}, got)
}

// Every key the example config documents under inboxes: is a known setting, so
// the startup warning never fires on documented configuration.
func TestConfigExampleInboxKeysAreAllKnown(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.yaml")
	require.NoError(t, err)
	var out []string
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "# inboxes:" {
			in = true
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		out = append(out, strings.TrimPrefix(strings.TrimPrefix(line, "#"), " "))
	}
	require.NotEmpty(t, out, "the example config must carry a commented inboxes block")
	got, err := UnknownKeys([]byte(strings.Join(out, "\n")))
	require.NoError(t, err)
	assert.Empty(t, got, "a documented key is reported as unknown")
}

// A per-sender rule has no gate of its own, so a gate setting there would do
// nothing; it fails load and says where the setting belongs.
func TestParseRejectsGateSettingsInsideARule(t *testing.T) {
	y := strings.Replace(knownInbox, "          level: untrusted\n", "          level: untrusted\n          require_authenticated: true\n", 1)
	_, err := Parse([]byte(y))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inboxes[0].trust.rules[0].require_authenticated")
	assert.Contains(t, err.Error(), "as trust.require_authenticated")
}
