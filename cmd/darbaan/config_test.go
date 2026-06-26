package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

// resolveAddr parses a CLI with the given config file, env, and args and returns
// the resolved listener-addr — the probe for layering precedence. (listener-addr
// is not a path flag, so its value is compared verbatim.)
func resolveAddr(t *testing.T, fileVal, envVal string, args []string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("listener-addr: "+fileVal+"\n"), 0o600))

	_ = os.Unsetenv("DARBAAN_LISTENER_ADDR")
	if envVal != "" {
		t.Setenv("DARBAAN_LISTENER_ADDR", envVal)
	}

	var cli CLI
	parser, err := kong.New(&cli, kongOptions(path)...)
	require.NoError(t, err)
	// "version" is a no-op leaf command; we only care about the resolved flags.
	_, err = parser.Parse(append([]string{"version"}, args...))
	require.NoError(t, err)
	return cli.ListenerAddr
}

// TestConfigPrecedence is the #16 deliverable: confirm file < env < flag.
func TestConfigPrecedence(t *testing.T) {
	t.Run("file only", func(t *testing.T) {
		require.Equal(t, "from-file", resolveAddr(t, "from-file", "", nil))
	})
	t.Run("env overrides file", func(t *testing.T) {
		require.Equal(t, "from-env", resolveAddr(t, "from-file", "from-env", nil))
	})
	t.Run("flag overrides env and file", func(t *testing.T) {
		require.Equal(t, "from-flag",
			resolveAddr(t, "from-file", "from-env", []string{"--listener-addr", "from-flag"}))
	})
	t.Run("flag overrides file (no env)", func(t *testing.T) {
		require.Equal(t, "from-flag",
			resolveAddr(t, "from-file", "", []string{"--listener-addr", "from-flag"}))
	})
}

// parseCLI builds and parses a CLI, resolving the config path the same way main
// does (so DARBAAN_CONFIG is honored).
func parseCLI(t *testing.T, args []string) CLI {
	t.Helper()
	var cli CLI
	parser, err := kong.New(&cli, kongOptions(resolveConfigPath(args))...)
	require.NoError(t, err)
	_, err = parser.Parse(args)
	require.NoError(t, err)
	return cli
}

// TestConfigFileSelectableByEnv covers #21(1): DARBAAN_CONFIG selects which
// config file loads, and --config still wins over it.
func TestConfigFileSelectableByEnv(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "env.yaml")
	require.NoError(t, os.WriteFile(envFile, []byte("listener-addr: from-env-config\n"), 0o600))

	t.Run("DARBAAN_CONFIG selects the file", func(t *testing.T) {
		t.Setenv("DARBAAN_CONFIG", envFile)
		cli := parseCLI(t, []string{"version"})
		require.Equal(t, "from-env-config", cli.ListenerAddr)
	})

	t.Run("--config wins over DARBAAN_CONFIG", func(t *testing.T) {
		flagFile := filepath.Join(t.TempDir(), "flag.yaml")
		require.NoError(t, os.WriteFile(flagFile, []byte("listener-addr: from-flag-config\n"), 0o600))
		t.Setenv("DARBAAN_CONFIG", envFile)
		cli := parseCLI(t, []string{"--config", flagFile, "version"})
		require.Equal(t, "from-flag-config", cli.ListenerAddr)
	})
}

// TestSliceEnvSplitting covers #21(2): a comma-separated env value sets a
// multi-element slice flag (so env-set approval chains don't collapse).
func TestSliceEnvSplitting(t *testing.T) {
	t.Run("comma-separated, trimmed", func(t *testing.T) {
		t.Setenv("DARBAAN_APPROVAL_STRICT", "alpha, beta ,gamma")
		cli := parseCLI(t, []string{"version"})
		require.Equal(t, []string{"alpha", "beta", "gamma"}, cli.ApprovalStrict)
	})

	t.Run("empty env does not override default", func(t *testing.T) {
		t.Setenv("DARBAAN_APPROVAL_STRICT", "")
		cli := parseCLI(t, []string{"version"})
		require.Equal(t, []string{"manual"}, cli.ApprovalStrict) // default preserved
	})
}
