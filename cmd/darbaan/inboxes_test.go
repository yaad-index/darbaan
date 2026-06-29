package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/inbound"
)

func TestResolveInboxesImplicitDefault(t *testing.T) {
	// No inboxes: config → one implicit "default" inbox built from the flat flags,
	// carrying the legacy --inbound-filter as its filter_file (ADR 0023 back-compat).
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(rules, []byte("default_visibility: visible\n"), 0o600))
	cli := parseCLI(t, []string{
		"--inbound-filter", rules,
		"--inbound-imap-host", "imap.example:993",
		"version",
	})
	inboxes, err := cli.resolveInboxes()
	require.NoError(t, err)
	require.Len(t, inboxes, 1)
	assert.Equal(t, inbound.DefaultInbox, inboxes[0].Name)
	assert.Equal(t, rules, inboxes[0].FilterFile)
	assert.Equal(t, "imap.example:993", inboxes[0].Backend.IMAPHost)
	// The implicit default's filter compiles from the legacy path.
	flt, err := inboxes[0].Filter()
	require.NoError(t, err)
	require.NotNil(t, flt)
}

func TestResolveInboxesFromConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"inboxes:\n"+
			"  - name: work\n    identity: agent@company.example\n"+
			"  - name: personal\n    default_visibility: hidden\n"), 0o600))

	cli := parseCLI(t, []string{"--config", cfg, "version"})
	inboxes, err := cli.resolveInboxes()
	require.NoError(t, err)
	require.Len(t, inboxes, 2)
	assert.Equal(t, "work", inboxes[0].Name)
	assert.Equal(t, "agent@company.example", inboxes[0].Identity)
	assert.Equal(t, "personal", inboxes[1].Name)
	assert.Equal(t, "hidden", inboxes[1].DefaultVisibility)
}
