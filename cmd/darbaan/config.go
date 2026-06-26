package main

import (
	"os"
	"strings"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
)

// envPrefix namespaces every config environment variable, e.g. the --sluice-db
// flag is also DARBAAN_SLUICE_DB.
const envPrefix = "DARBAAN_"

// defaultConfigPaths are searched in order; missing files are skipped. --config
// adds another path at higher file-precedence than the defaults.
var defaultConfigPaths = []string{"/etc/darbaan/config.yaml"}

// envResolver resolves any flag from DARBAAN_<NAME>, where NAME is the flag name
// uppercased with '-' and '.' turned into '_'.
//
// It is registered AFTER the file (config) resolver, and kong keeps the last
// resolved value, so env overrides the file. CLI flags still win because kong's
// resolution pass skips flags already set on the command line. The resulting
// precedence is therefore file < env < flag (asserted in config_test.go).
func envResolver() kong.Resolver {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return kong.ResolverFunc(func(_ *kong.Context, _ *kong.Path, flag *kong.Flag) (any, error) {
		name := envPrefix + strings.ToUpper(replacer.Replace(flag.Name))
		if v, ok := os.LookupEnv(name); ok {
			return v, nil
		}
		return nil, nil
	})
}

// kongOptions builds the parser options that establish the file < env < flag
// layering. extraConfigPath, when non-empty (from --config), is appended after
// the defaults so it outranks them but still sits below env and flags.
func kongOptions(extraConfigPath string) []kong.Option {
	paths := append([]string{}, defaultConfigPaths...)
	if extraConfigPath != "" {
		paths = append(paths, extraConfigPath)
	}
	return []kong.Option{
		// Order matters: file resolvers first, env resolver second (env wins).
		kong.Configuration(kongyaml.Loader, paths...),
		kong.Resolvers(envResolver()),
		kong.Name("darbaan"),
		kong.Description("Darbaan mail-gate proxy. See the adr/ directory for the design."),
		kong.UsageOnError(),
	}
}

// configPathFromArgs scans for --config so its file can be added to the loader
// paths before kong parses (the loader paths are fixed at construction time).
func configPathFromArgs(args []string) string {
	for i, a := range args {
		switch {
		case a == "--config" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return ""
}
