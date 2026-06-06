package main

import (
	"fmt"
	"os/exec"
)

// preflightExecutable validates the caller-supplied command path/name before
// any secret value is copied into an exec environment string. exec.Command
// would otherwise defer this failure until Start, after Cmd.Env has already
// been populated with plaintext secrets.
func preflightExecutable(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("empty command")
	}
	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("resolve command %q: %w", cmd, err)
	}
	return nil
}

// clearEnvStrings drops references to environment strings that may contain
// plaintext secret values. Go strings are immutable, so this cannot erase their
// backing bytes; it only makes the slices we control stop retaining them.
func clearEnvStrings(env []string) {
	for i := range env {
		env[i] = ""
	}
}
