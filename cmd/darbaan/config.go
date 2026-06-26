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
		v, ok := os.LookupEnv(name)
		if !ok {
			return nil, nil
		}
		// kong does not split a single resolver string into slice elements, so
		// for slice flags (e.g. approval-strict) split the comma-separated env
		// value ourselves — matching how the YAML and repeated-flag paths build
		// multi-element chains. Without this, DARBAAN_APPROVAL_STRICT="a,b" would
		// collapse to a single "a,b" element.
		if flag.IsSlice() {
			// kong's slice decoder splits the returned string on the flag's
			// separator (comma) but does not trim, so normalize first: trim and
			// drop empties, then rejoin for kong to re-split. A comma-separated
			// env value such as DARBAAN_APPROVAL_STRICT="a, b" thus yields a
			// clean multi-element chain ["a","b"]; an empty value does not
			// override a non-empty default with an empty chain.
			parts := splitComma(v)
			if len(parts) == 0 {
				return nil, nil
			}
			return strings.Join(parts, ","), nil
		}
		return v, nil
	})
}

// splitComma splits a comma-separated env value into trimmed, non-empty
// elements. An empty (or whitespace-only) value yields no elements.
func splitComma(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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

// resolveConfigPath determines which config file to add to the loader paths
// before kong parses (the loader paths are fixed at construction time, so this
// runs before the resolvers). The --config flag wins; otherwise DARBAAN_CONFIG
// is honored, so an operator can select the config file by env as well — flag
// over env, consistent with the rest of the layering.
func resolveConfigPath(args []string) string {
	for i, a := range args {
		switch {
		case a == "--config" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return os.Getenv(envPrefix + "CONFIG")
}
