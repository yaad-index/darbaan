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
