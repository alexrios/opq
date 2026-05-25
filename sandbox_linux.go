//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// bwrapMinMajor / bwrapMinMinor: floor that supports all the flags
// we emit (--die-with-parent, --unshare-net, --new-session, --cap-drop).
// 0.5.0 is the earliest release that has the full set.
const (
	bwrapMinMajor = 0
	bwrapMinMinor = 5
)

// VerifySandboxAvailable returns nil if the sandbox profiles other
// than SandboxNone will work on this host. It checks for bwrap on
// PATH at a sufficient version, and that unprivileged user
// namespaces are available — the kernel feature bwrap uses to apply
// the namespace flags without setuid.
func VerifySandboxAvailable() error {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("bubblewrap (bwrap) not found in PATH: install it via your package manager (Debian/Ubuntu: apt install bubblewrap; Fedora: dnf install bubblewrap; Arch: pacman -S bubblewrap)")
	}
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("bwrap --version failed: %w", err)
	}
	major, minor, perr := parseBwrapVersion(string(out))
	if perr != nil {
		return fmt.Errorf("parse bwrap version %q: %w", strings.TrimSpace(string(out)), perr)
	}
	if major < bwrapMinMajor || (major == bwrapMinMajor && minor < bwrapMinMinor) {
		return fmt.Errorf("bwrap version %d.%d is too old; need >= %d.%d", major, minor, bwrapMinMajor, bwrapMinMinor)
	}
	if err := checkUnprivilegedUserns(); err != nil {
		return err
	}
	return nil
}

// parseBwrapVersion extracts a major.minor pair from the output of
// `bwrap --version`. Typical output: "bubblewrap 0.11.0".
func parseBwrapVersion(s string) (int, int, error) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("unexpected version output")
	}
	verToken := fields[len(fields)-1]
	parts := strings.Split(verToken, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("version token %q lacks major.minor", verToken)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("major: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("minor: %w", err)
	}
	return major, minor, nil
}

// checkUnprivilegedUserns probes for kernel support for unprivileged
// user namespaces. Distros that disable them (some Debian/Ubuntu
// configs) expose
// /proc/sys/kernel/unprivileged_userns_clone = 0. Absence of the
// file is treated as "enabled" since upstream kernels default to on
// and only some distros add the sysctl.
func checkUnprivilegedUserns() error {
	const p = "/proc/sys/kernel/unprivileged_userns_clone"
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", p, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "0" {
		return fmt.Errorf("unprivileged user namespaces are disabled (sysctl %s=0); enable with 'sysctl -w kernel.unprivileged_userns_clone=1'", p)
	}
	return nil
}

// WrapCommand returns the argv to feed to exec.Command for running
// `cmd args...` under the chosen profile. For SandboxNone the call
// is a no-op passthrough. For SandboxNet / SandboxFull, the command
// is resolved to an absolute path via PATH on the host first (bwrap
// then exec's that absolute path inside the sandbox — the host PATH
// lookup must happen before the FS view changes).
func WrapCommand(profile SandboxProfile, cmd string, args []string) (string, []string, error) {
	if cmd == "" {
		return "", nil, fmt.Errorf("empty command")
	}
	if profile == SandboxNone {
		return cmd, args, nil
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return "", nil, fmt.Errorf("bubblewrap (bwrap) not found in PATH: %w", err)
	}
	abs, err := exec.LookPath(cmd)
	if err != nil {
		return "", nil, fmt.Errorf("resolve command %q: %w", cmd, err)
	}

	var bwArgs []string
	switch profile {
	case SandboxNet:
		bwArgs = []string{
			"--dev-bind", "/", "/",
			"--unshare-net",
			"--tmpfs", "/dev/shm",
			"--die-with-parent",
			"--new-session",
		}
	case SandboxFull:
		bwArgs = []string{
			"--unshare-all",
			"--ro-bind", "/usr", "/usr",
			"--ro-bind-try", "/etc", "/etc",
			"--ro-bind-try", "/lib", "/lib",
			"--ro-bind-try", "/lib64", "/lib64",
			"--ro-bind-try", "/bin", "/bin",
			"--ro-bind-try", "/sbin", "/sbin",
			"--proc", "/proc",
			"--dev", "/dev",
			"--tmpfs", "/tmp",
			"--tmpfs", "/home",
			"--tmpfs", "/dev/shm",
			"--setenv", "HOME", "/tmp",
			"--setenv", "PATH", "/usr/bin:/usr/sbin:/bin:/sbin",
			"--new-session",
			"--die-with-parent",
			"--cap-drop", "ALL",
		}
	default:
		return "", nil, fmt.Errorf("unknown sandbox profile %d", profile)
	}

	full := make([]string, 0, len(bwArgs)+2+len(args))
	full = append(full, bwArgs...)
	full = append(full, "--", abs)
	full = append(full, args...)
	return bwrap, full, nil
}
