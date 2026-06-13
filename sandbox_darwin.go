//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// macOS subprocess sandbox, the Seatbelt counterpart to sandbox_linux.go's
// bwrap backend. Where Linux composes namespaces + bind mounts via bwrap, macOS
// has no equivalent; the platform mechanism is `sandbox-exec` driving a Seatbelt
// profile written in SBPL (Sandbox Profile Language). sandbox-exec is formally
// deprecated by Apple but ships on every macOS release and remains the same
// primitive Chromium, nix, and Homebrew rely on for process isolation; there is
// no supported replacement at the CLI layer.
//
// Guarantee parity with Linux SandboxNet/SandboxFull (see sandbox.go):
//   - external network egress is blocked (the core "AI can't exfil a secret"
//     property). `(deny network*)` also blocks AF_UNIX connect(), so credential
//     agents (gpg-agent, ssh-agent) reachable by socket are closed under
//     SandboxNet without a per-socket mask.
//   - the host filesystem is readable but read-only (`(deny file-write*)`),
//     matching `--ro-bind / /`. Even /dev/null is non-writable, exactly as on
//     Linux under `--ro-bind / /`.
//   - the audit log directory and the operator's credential stores are masked
//     from reads so an AI subprocess can't recover filtered audit tokens or
//     agent sockets the way it can't on Linux.
//
// Known divergences from the Linux backend, called out so they are not mistaken
// for parity:
//   - Linux SandboxNet exposes an EMPTY tmpfs at /tmp (writable + isolated).
//     Seatbelt can only allow or deny a path, not overlay an empty one, so the
//     macOS profile denies ALL writes instead. This is strictly stronger for
//     the cross-call persistence threat (call-1 can't stage a secret in /tmp
//     for call-2 to read), at the cost that commands needing scratch space fail
//     under the sandbox; such commands should run via the CLI with
//     -sandbox=none after operator review.
//   - SandboxFull here is allow-default with targeted denies (network, writes,
//     $HOME and the temp dirs) rather than Linux's deny-default
//     `--unshare-all` + minimal binds. It delivers the documented SandboxFull
//     guarantee ("blocks external network egress, and reads of $HOME and /tmp")
//     but is less hermetic than the Linux profile. A deny-default SBPL profile
//     that still lets arbitrary binaries dyld-load reliably is far more fragile,
//     so we trade hermeticity for robustness here.

// sandboxExecPath is the absolute path to the Seatbelt launcher. It is a fixed
// system binary; we still LookPath in VerifySandboxAvailable so a stripped PATH
// surfaces a clear error rather than an exec failure at run time.
const sandboxExecBin = "sandbox-exec"

var (
	sandboxVerifyOnce    sync.Once
	sandboxVerifyOnceErr error
)

// VerifySandboxAvailable returns nil if non-None profiles will work here:
// sandbox-exec on PATH and able to apply a trivial profile. The result is
// cached for the process lifetime; the probe forks sandbox-exec (~10-30ms) and
// the host's Seatbelt availability is stable, so re-probing only burns cycles.
// See resetSandboxVerifyCacheForTest for the test hook.
func VerifySandboxAvailable() error {
	sandboxVerifyOnce.Do(func() {
		sandboxVerifyOnceErr = verifySandboxAvailableUncached()
	})
	return sandboxVerifyOnceErr
}

// verifySandboxAvailableUncached performs the actual probe without caching.
// Split out so the sync.Once wrapper stays trivial and tests can drive the
// underlying logic after resetSandboxVerifyCacheForTest.
func verifySandboxAvailableUncached() error {
	path, err := exec.LookPath(sandboxExecBin)
	if err != nil {
		return fmt.Errorf("sandbox-exec not found in PATH: it ships with macOS at /usr/bin/sandbox-exec; a stripped PATH or non-macOS host can't sandbox")
	}
	// Functional probe: apply a trivial allow-all profile to /usr/bin/true.
	// A host where Seatbelt is wedged (rare, but possible under MDM policy)
	// fails here at startup, the same way a real call would, rather than as an
	// obscure run_with_secrets failure later.
	probe := exec.Command(path, "-p", "(version 1)(allow default)", "/usr/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		return fmt.Errorf("sandbox-exec probe failed (Seatbelt may be disabled by policy): %w; sandbox-exec output: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// resetSandboxVerifyCacheForTest clears the sync.Once cache so a subsequent
// VerifySandboxAvailable call re-probes the host. Used by tests that manipulate
// PATH. NOT for production code.
func resetSandboxVerifyCacheForTest() {
	sandboxVerifyOnce = sync.Once{}
	sandboxVerifyOnceErr = nil
}

// homeDirForMask returns the operator's $HOME for building deny-read paths.
// Indirected (like the Linux backend) so tests can override without t.Setenv on
// a process-global, which would race parallel tests. Production calls
// os.UserHomeDir.
var homeDirForMask = func() (string, error) {
	return os.UserHomeDir()
}

// resolveAuditDirForMask returns the absolute, symlink-resolved path of the
// audit directory so the SandboxNet profile can deny reads of it. The directory
// is created first (with prepareAuditDir's 0700 + symlink-refusal semantics) and
// symlinks are resolved because the kernel canonicalizes a path (e.g.
// /tmp -> /private/tmp on macOS) before applying the Seatbelt check, so the deny
// rule must name the canonical path to match.
func resolveAuditDirForMask() (string, error) {
	p, err := auditLogPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(p)
	if err := prepareAuditDir(dir); err != nil {
		return "", fmt.Errorf("prepare audit dir for sandbox mask: %w", err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("evalsymlinks audit dir: %w", err)
	}
	return real, nil
}

// homeCredentialReadDenies lists $HOME-relative paths whose reads are denied
// under the FS sandbox, mirroring sandbox_linux.go's homeDirSocketTmpfsRel /
// homeDirSocketFileRel. Denying reads hides both the credential material and the
// agent socket file, so connect() can't find it even under SandboxNetAllowed
// where network() is permitted. As on Linux, masking .gnupg breaks gpg run
// inside the sandbox; the trade is intentional (the sandbox is for arbitrary AI
// commands, not the operator's keys).
var homeCredentialReadDenies = []string{
	".gnupg",                  // gpg-agent socket family + private keys
	".docker/run/docker.sock", // rootless Docker (Docker Desktop) API socket
	".ssh",                    // ssh private keys (Linux leaves these readable under
	// SandboxNet, but on macOS the ssh-agent socket is commonly under $HOME or
	// $SSH_AUTH_SOCK; denying the dir is strictly safer and cheap)
}

// buildSeatbeltProfile renders the SBPL profile for a non-None profile. It
// returns an error (and the caller fails closed) when a required path can't be
// resolved, matching the Linux backend's fail-closed contract for the audit dir.
func buildSeatbeltProfile(profile SandboxProfile) (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")

	switch profile {
	case SandboxNet, SandboxNetAllowed:
		if profile == SandboxNet {
			// SandboxNet drops the network; SandboxNetAllowed keeps it but
			// retains the FS sandbox so a network-allowed call can't persist a
			// secret to disk for a later sandboxed call to read back.
			b.WriteString("(deny network*)\n")
		}
		// Read-only host FS, matching --ro-bind / /.
		b.WriteString("(deny file-write*)\n")

		home, herr := homeDirForMask()
		if herr == nil && home != "" {
			for _, rel := range homeCredentialReadDenies {
				b.WriteString("(deny file-read* " + sbplSubpath(filepath.Join(home, rel)) + ")\n")
			}
		}
		// $SSH_AUTH_SOCK is the operator's (parent env; the AI can't influence
		// it). Deny reads of the literal socket path so the agent is unreachable
		// even under SandboxNetAllowed, mirroring Linux's /run/user tmpfs mask.
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			b.WriteString("(deny file-read* " + sbplLiteral(sock) + ")\n")
		}

		// Mask the audit dir so the child can't cat audit.log and recover the
		// raw tokens filterAuditMessageForAI strips from the MCP response.
		auditDir, err := resolveAuditDirForMask()
		if err != nil {
			return "", fmt.Errorf("resolve audit dir for sandbox mask: %w", err)
		}
		b.WriteString("(deny file-read* " + sbplSubpath(auditDir) + ")\n")

	case SandboxFull:
		b.WriteString("(deny network*)\n")
		b.WriteString("(deny file-write*)\n")
		// Block $HOME and the temp dirs wholesale, the macOS analogue of
		// Linux's tmpfs over /home and /tmp. /Users covers every user home
		// without depending on resolving $HOME (so SandboxFull does not gain a
		// failure mode on an unset HOME, matching the Linux contract). The
		// resolved $HOME is added too in case it lives outside /Users.
		b.WriteString("(deny file-read* (subpath \"/Users\"))\n")
		b.WriteString("(deny file-read* (subpath \"/private/var/root\"))\n")
		if home, err := homeDirForMask(); err == nil && home != "" && !strings.HasPrefix(home, "/Users/") {
			b.WriteString("(deny file-read* " + sbplSubpath(home) + ")\n")
		}
		for _, tmp := range []string{"/tmp", "/private/tmp", "/private/var/tmp", "/private/var/folders"} {
			b.WriteString("(deny file-read* (subpath \"" + tmp + "\"))\n")
		}

	default:
		return "", fmt.Errorf("unknown sandbox profile %d", profile)
	}

	return b.String(), nil
}

// WrapCommand returns the argv to run `cmd args...` under the given profile via
// sandbox-exec. SandboxNone is a passthrough. Otherwise cmd is resolved to an
// absolute path on the HOST first (the PATH lookup must precede the sandbox),
// and a generated SBPL profile is passed inline with -p.
func WrapCommand(profile SandboxProfile, cmd string, args []string) (string, []string, error) {
	if cmd == "" {
		return "", nil, fmt.Errorf("empty command")
	}
	if profile == SandboxNone {
		return cmd, args, nil
	}
	sbx, err := exec.LookPath(sandboxExecBin)
	if err != nil {
		return "", nil, fmt.Errorf("sandbox-exec not found in PATH: %w", err)
	}
	abs, err := exec.LookPath(cmd)
	if err != nil {
		return "", nil, fmt.Errorf("resolve command %q: %w", cmd, err)
	}
	prof, err := buildSeatbeltProfile(profile)
	if err != nil {
		return "", nil, err
	}

	// sandbox-exec -p <profile> <abs-cmd> <args...>. Once sandbox-exec reaches
	// the command token, the remaining args belong to the child and are not
	// reparsed as sandbox-exec flags, so args beginning with '-' are safe.
	full := make([]string, 0, 3+len(args))
	full = append(full, "-p", prof, abs)
	full = append(full, args...)
	return sbx, full, nil
}

// sbplSubpath renders a `(subpath "...")` SBPL filter with the path escaped.
func sbplSubpath(p string) string {
	return "(subpath " + sbplString(p) + ")"
}

// sbplLiteral renders a `(literal "...")` SBPL filter with the path escaped.
func sbplLiteral(p string) string {
	return "(literal " + sbplString(p) + ")"
}

// sbplString renders a Go string as an SBPL double-quoted literal, escaping the
// only two characters that are syntactically significant inside one: backslash
// and double-quote. macOS paths almost never contain either, but a path that
// did would otherwise break out of the quoted string and corrupt the profile.
func sbplString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
