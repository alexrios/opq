//go:build !linux && !darwin

package main

import "fmt"

// VerifySandboxAvailable reports that sandboxing is unavailable on
// this OS. opq's subprocess sandbox is implemented for Linux (bwrap)
// and macOS (sandbox-exec / Seatbelt) only.
func VerifySandboxAvailable() error {
	return fmt.Errorf("subprocess sandbox not supported on this OS (Linux and macOS only)")
}

// resetSandboxVerifyCacheForTest is a no-op on platforms without a
// backend; there is no sync.Once cache here because
// VerifySandboxAvailable is a constant error and never worth caching.
// Provided so cross-platform test code can call the helper without
// build tags.
func resetSandboxVerifyCacheForTest() {}

// WrapCommand returns cmd+args unchanged for SandboxNone and errors
// for any other profile (including SandboxNet, SandboxNetAllowed, and
// SandboxFull) since no backend exists for this OS.
func WrapCommand(profile SandboxProfile, cmd string, args []string) (string, []string, error) {
	if cmd == "" {
		return "", nil, fmt.Errorf("empty command")
	}
	if profile == SandboxNone {
		return cmd, args, nil
	}
	return "", nil, fmt.Errorf("subprocess sandbox not supported on this OS (Linux and macOS only)")
}
