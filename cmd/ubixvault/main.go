// Command ubixvault is the uBix Vault server and CLI.
//
// This is an early scaffold: the storage layer exists and is tested, but no
// server or command surface is wired up yet. See docs/ROADMAP.md.
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	fmt.Printf("uBix Vault %s\n", version)
	fmt.Fprintln(os.Stderr, "not yet implemented: see docs/ROADMAP.md")
}
