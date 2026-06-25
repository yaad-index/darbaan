// Command darbaan is the Darbaan mail-gate proxy CLI.
//
// This is the thin entry point: it parses flags and loads configuration only.
// All behavior lives in the library packages under internal/ and pkg/. See the
// adr/ directory for the design.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is the build version, overridden at link time via -ldflags.
var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("darbaan", version)
		return
	}

	// Wiring of the listeners, sluice, approver pipeline, backends, and audit
	// log lands with their respective components. The skeleton has no behavior.
	_ = configPath
	fmt.Fprintln(os.Stderr, "darbaan: not yet implemented")
	os.Exit(1)
}
