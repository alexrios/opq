package main

import (
	"fmt"
	"strings"
)

// backendName is the process-wide backend selector. It is set once in run()
// (main.go) after kong.Parse has folded in the --backend flag and the
// OPQ_BACKEND env var, and before ctx.Run() spawns anything. It is only read
// thereafter (including by MCP handler goroutines, which start inside
// ctx.Run()), so it needs no synchronization.
var backendName string

// openBackend constructs the named backend. This switch is the single tight
// allowlist for backend selection: an unknown name is a HARD error, never a
// silent fallback to an unencrypted store (the "Adding a backend" invariant in
// CLAUDE.md). The empty string maps to the keyring so the no-flag/no-env case
// behaves exactly as opq did before this selector existed.
func openBackend(name string) (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "keyring":
		return openKeyringBackend()
	case "vault":
		return openVaultBackend()
	case "proton-pass":
		return openProtonBackend()
	default:
		return nil, fmt.Errorf("unknown backend %q (want one of: keyring, vault, proton-pass)", name)
	}
}
