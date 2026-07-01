package agentcfg_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/agentcfg"
)

func inboxSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestParseAgents(t *testing.T) {
	agents, err := agentcfg.Parse([]byte(`
inboxes:
  - name: inbox-a
agents:
  - name: agent-a
    default_inbox: inbox-a
    grants:
      - { inbox: inbox-a, access: [read, send] }
      - { inbox: inbox-b, access: [read] }
`))
	require.NoError(t, err)
	require.Len(t, agents, 1)
	assert.Equal(t, "agent-a", agents[0].Name)
	assert.Equal(t, "inbox-a", agents[0].DefaultInbox)
	require.Len(t, agents[0].Grants, 2)
	assert.Equal(t, []string{"read", "send"}, agents[0].Grants[0].Access)
}

// An absent agents: list yields nil — the caller substitutes the implicit agent.
func TestParseNoAgents(t *testing.T) {
	agents, err := agentcfg.Parse([]byte("inboxes:\n  - name: inbox-a\n"))
	require.NoError(t, err)
	assert.Nil(t, agents)
}

func TestPasswordEnv(t *testing.T) {
	assert.Equal(t, "DARBAAN_AGENT_AGENT_A_PASSWORD", agentcfg.PasswordEnv("agent-a"))
	// The mangle is many-to-one: '-' and '_' both fold to '_'.
	assert.Equal(t, agentcfg.PasswordEnv("a-b"), agentcfg.PasswordEnv("a_b"))
}

func TestValidateOK(t *testing.T) {
	agents := []agentcfg.Agent{{
		Name:         "agent-a",
		DefaultInbox: "inbox-a",
		Grants: []agentcfg.Grant{
			{Inbox: "inbox-a", Access: []string{"read", "send"}},
			{Inbox: "inbox-b", Access: []string{"read"}},
		},
	}}
	require.NoError(t, agentcfg.Validate(agents, inboxSet("inbox-a", "inbox-b")))
}

func TestValidateEmpty(t *testing.T) {
	require.Error(t, agentcfg.Validate(nil, inboxSet("inbox-a")))
}

func TestValidateDuplicateName(t *testing.T) {
	agents := []agentcfg.Agent{
		{Name: "agent-a", Grants: []agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read"}}}},
		{Name: "agent-a", Grants: []agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read"}}}},
	}
	err := agentcfg.Validate(agents, inboxSet("inbox-a"))
	require.ErrorContains(t, err, "duplicate agent name")
}

// Names that mangle to the same password env must be rejected even though the raw
// names differ, or two agents would silently share one secret.
func TestValidateEnvCollision(t *testing.T) {
	agents := []agentcfg.Agent{
		{Name: "a-b", Grants: []agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read"}}}},
		{Name: "a_b", Grants: []agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read"}}}},
	}
	err := agentcfg.Validate(agents, inboxSet("inbox-a"))
	require.ErrorContains(t, err, "same password env")
}

func TestValidateGrantErrors(t *testing.T) {
	cases := map[string]struct {
		grants []agentcfg.Grant
		want   string
	}{
		"no grants":       {nil, "at least one grant"},
		"unknown inbox":   {[]agentcfg.Grant{{Inbox: "nope", Access: []string{"read"}}}, "unknown inbox"},
		"empty access":    {[]agentcfg.Grant{{Inbox: "inbox-a", Access: nil}}, "empty access"},
		"bad access":      {[]agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"write"}}}, "unknown access"},
		"repeat access":   {[]agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read", "read"}}}, "repeats access"},
		"duplicate grant": {[]agentcfg.Grant{{Inbox: "inbox-a", Access: []string{"read"}}, {Inbox: "inbox-a", Access: []string{"send"}}}, "duplicate grant"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			agents := []agentcfg.Agent{{Name: "agent-a", DefaultInbox: "inbox-a", Grants: tc.grants}}
			require.ErrorContains(t, agentcfg.Validate(agents, inboxSet("inbox-a")), tc.want)
		})
	}
}

func TestDefaultInboxExplicit(t *testing.T) {
	got, err := agentcfg.DefaultInbox(agentcfg.Agent{
		Name:         "agent-a",
		DefaultInbox: "inbox-a",
		Grants: []agentcfg.Grant{
			{Inbox: "inbox-a", Access: []string{"read"}},
			{Inbox: "inbox-b", Access: []string{"read"}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "inbox-a", got)
}

// `default: true` on a grant is sugar for the field.
func TestDefaultInboxMarkedGrant(t *testing.T) {
	got, err := agentcfg.DefaultInbox(agentcfg.Agent{
		Name: "agent-a",
		Grants: []agentcfg.Grant{
			{Inbox: "inbox-a", Access: []string{"read"}},
			{Inbox: "inbox-b", Access: []string{"read"}, Default: true},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "inbox-b", got)
}

// A lone read grant is inferred as the default.
func TestDefaultInboxInferred(t *testing.T) {
	got, err := agentcfg.DefaultInbox(agentcfg.Agent{
		Name: "agent-a",
		Grants: []agentcfg.Grant{
			{Inbox: "inbox-a", Access: []string{"read", "send"}},
			{Inbox: "inbox-b", Access: []string{"send"}}, // send-only, not a default candidate
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "inbox-a", got)
}

func TestDefaultInboxErrors(t *testing.T) {
	cases := map[string]struct {
		agent agentcfg.Agent
		want  string
	}{
		"ambiguous two read grants": {
			agentcfg.Agent{Name: "agent-a", Grants: []agentcfg.Grant{
				{Inbox: "inbox-a", Access: []string{"read"}},
				{Inbox: "inbox-b", Access: []string{"read"}},
			}},
			"default_inbox is required",
		},
		// A send-only default_inbox would be an un-SELECTable INBOX.
		"send-only default": {
			agentcfg.Agent{Name: "agent-a", DefaultInbox: "inbox-a", Grants: []agentcfg.Grant{
				{Inbox: "inbox-a", Access: []string{"send"}},
			}},
			"must have read access",
		},
		"default not granted": {
			agentcfg.Agent{Name: "agent-a", DefaultInbox: "inbox-z", Grants: []agentcfg.Grant{
				{Inbox: "inbox-a", Access: []string{"read"}},
			}},
			"not a granted inbox",
		},
		"no read grant at all": {
			agentcfg.Agent{Name: "agent-a", Grants: []agentcfg.Grant{
				{Inbox: "inbox-a", Access: []string{"send"}},
			}},
			"no read grant",
		},
		"conflicting field and marked grant": {
			agentcfg.Agent{Name: "agent-a", DefaultInbox: "inbox-a", Grants: []agentcfg.Grant{
				{Inbox: "inbox-a", Access: []string{"read"}},
				{Inbox: "inbox-b", Access: []string{"read"}, Default: true},
			}},
			"conflicts with the grant marked default",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := agentcfg.DefaultInbox(tc.agent)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
