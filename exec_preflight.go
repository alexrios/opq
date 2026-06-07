package main

import (
	"fmt"
	"os/exec"
)

// preflightExecutable resolves cmd before secret-backed env strings are built.
func preflightExecutable(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("empty command")
	}
	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("resolve command %q: %w", cmd, err)
	}
	return nil
}

// clearEnvStrings drops slice-held references to environment strings.
func clearEnvStrings(env []string) {
	for i := range env {
		env[i] = ""
	}
}
