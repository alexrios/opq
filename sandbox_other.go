//go:build !linux

package main

import "fmt"

// VerifySandboxAvailable reports that sandboxing is unavailable on
// this OS. opq's bwrap-based sandbox is Linux-only.
func VerifySandboxAvailable() error {
	return fmt.Errorf("subprocess sandbox not supported on this OS (Linux only)")
}

// WrapCommand returns cmd+args unchanged for SandboxNone and errors
// for any other profile, since no non-Linux backend exists yet.
func WrapCommand(profile SandboxProfile, cmd string, args []string) (string, []string, error) {
	if cmd == "" {
		return "", nil, fmt.Errorf("empty command")
	}
	if profile == SandboxNone {
		return cmd, args, nil
	}
	return "", nil, fmt.Errorf("subprocess sandbox not supported on this OS (Linux only)")
}
