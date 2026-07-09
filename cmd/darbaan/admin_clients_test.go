package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yaad-index/darbaan/internal/admincfg"
)

func TestResolveAdminClientsFromConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"admin_clients:\n"+
			"  - name: telegram\n    scopes: [queue:read, queue:decide, holds:read, holds:decide, reconcile:read]\n"+
			"  - name: pre-screener\n    scopes: [queue:read, holds:read]\n"), 0o600))
	// telegram's token is set; pre-screener's is intentionally unset → skipped + logged.
	t.Setenv("DARBAAN_ADMIN_TOKEN_TELEGRAM", "tg-tok")

	cli := parseCLI(t, []string{"--config", cfg, "version"})
	clients, err := cli.resolveAdminClients()
	require.NoError(t, err)
	require.Len(t, clients, 1, "only the client whose token env is set is returned")
	assert.Equal(t, "telegram", clients[0].Name)
	assert.Equal(t, "tg-tok", clients[0].Token)
	assert.Contains(t, clients[0].Scopes, admincfg.ScopeReconcileRead)
}

// No admin_clients: → nil, so the single DARBAAN_ADMIN_TOKEN root is the only
// credential (back-compat).
func TestResolveAdminClientsEmpty(t *testing.T) {
	cli := parseCLI(t, []string{"version"})
	clients, err := cli.resolveAdminClients()
	require.NoError(t, err)
	assert.Nil(t, clients)
}

// A malformed admin_clients: (unknown scope) fails at resolve, not at request
// time.
func TestResolveAdminClientsRejectsBadScope(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"admin_clients:\n  - name: x\n    scopes: [queue:write]\n"), 0o600))
	cli := parseCLI(t, []string{"--config", cfg, "version"})
	_, err := cli.resolveAdminClients()
	assert.Error(t, err)
}
