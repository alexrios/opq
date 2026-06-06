package main

// Subprocess sandboxing for opq.
//
// The MCP run_with_secrets tool lets an AI run an arbitrary command, which could
// move a resolved secret off-box via any network binary on $PATH (curl, DNS,
// TCP). Output redaction doesn't cover those paths — only accidental echo. This
// file is the platform-agnostic surface; sandbox_linux.go wraps commands in
// bwrap (network namespace + optional minimal FS view), and non-Linux
// (sandbox_other.go) accepts only SandboxNone.
//
// Blocks: external network egress, and (SandboxFull) reads of $HOME and /tmp.
// Does NOT block: loopback to co-resident services, timing side-channels,
// inherited kernel-keyring capabilities, or pre-compromised /usr binaries.

// SandboxProfile selects a child's isolation level. Not a strict ordering:
// SandboxNetAllowed lifts SandboxNet's netns but keeps its FS sandbox.
type SandboxProfile int

const (
	// SandboxNone runs the child with no isolation. CLI/operator only — no
	// MCP-reachable path routes here.
	SandboxNone SandboxProfile = iota
	// SandboxNet drops the network (unshare-net) while leaving the
	// host filesystem readable but read-only. This is the MCP default.
	SandboxNet
	// SandboxFull drops the network AND replaces /home and /tmp with
	// empty tmpfs mounts, exposing only minimal ro-binds for system
	// binaries and libraries.
	SandboxFull
	// SandboxNetAllowed lifts the netns but keeps SandboxNet's FS sandbox.
	// Used for MCP allow_network=true so one call can't persist secret material
	// on the host FS for a later call to read back.
	SandboxNetAllowed
)

// String renders the profile for human-facing messages and audit
// log entries.
func (p SandboxProfile) String() string {
	switch p {
	case SandboxNone:
		return "none"
	case SandboxNet:
		return "net"
	case SandboxFull:
		return "full"
	case SandboxNetAllowed:
		return "net-allowed"
	default:
		return "unknown"
	}
}
