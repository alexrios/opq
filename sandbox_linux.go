//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// J-9: a functional probe. The version + sysctl checks above are
	// necessary but not sufficient: AppArmor profiles (Ubuntu 23.10+
	// ships one for `bwrap` itself), seccomp on the host, or a missing
	// kernel CONFIG_USER_NS at runtime can each block namespace creation
	// even when the static checks pass. Run a no-op `true` under flags
	// that mirror WrapCommand's SandboxNet so failures here surface the
	// same way real run_with_secrets calls would. --ro-bind / / is
	// included for fidelity with the real SandboxNet argv — a host that
	// passes the probe is then more likely to pass real calls. The probe
	// runs `true` which exits instantly; on AppArmor-blocked hosts the
	// kernel returns EPERM immediately. No timeout / goroutine needed.
	probe := exec.Command(path,
		"--ro-bind", "/", "/",
		"--unshare-net", "--unshare-pid",
		"--die-with-parent", "--new-session",
		"true",
	)
	if out, err := probe.CombinedOutput(); err != nil {
		return fmt.Errorf("bwrap namespace probe failed (host may block unprivileged userns / have an AppArmor profile on bwrap): %w; bwrap output: %s", err, strings.TrimSpace(string(out)))
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

// resolveAuditDirForMask returns the absolute, symlink-resolved path of
// the audit directory so SandboxNet can tmpfs-mask it. The directory is
// created first (with prepareAuditDir's 0700 + symlink-refusal semantics)
// because bwrap's --tmpfs requires the mount target to already exist.
func resolveAuditDirForMask() (string, error) {
	p, err := auditLogPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(p)
	// Ensure dir exists (bwrap --tmpfs requires the target dir to exist).
	// Use prepareAuditDir which already handles symlink refusal + 0700 mode.
	if err := prepareAuditDir(dir); err != nil {
		return "", fmt.Errorf("prepare audit dir for sandbox mask: %w", err)
	}
	// Defense-in-depth: resolve symlinks so the tmpfs lands on the real
	// inode. Mount semantics already follow the path lookup at mount(2)
	// time, so a symlink-prefixed dir is masked correctly today; resolving
	// here insulates against future bwrap behavior changes and TOCTOU
	// shenanigans where the symlink is swapped between resolve and mount.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("evalsymlinks audit dir: %w", err)
	}
	return real, nil
}

// sandboxNetArgvCommon returns the bwrap argv shared by SandboxNet and
// SandboxNetAllowed. The two profiles differ only by whether the
// caller adds --unshare-net; everything else (read-only host bind,
// tmpfs masks on the socket/tmp/dev-shm/audit dirs, private PID
// namespace, --die-with-parent, --new-session) is identical.
//
// Ordering is load-bearing:
//   - --ro-bind / / must be FIRST so subsequent --tmpfs entries
//     shadow the host bind-mounts (bwrap applies mounts L→R).
//   - --proc /proc must come AFTER --ro-bind / / so it masks the host
//     procfs (PID-namespace isolation depends on this — finding C2).
//
// J-1: --unshare-net only blocks AF_INET/INET6/PACKET/NETLINK. AF_UNIX
// sockets reachable by filesystem path (e.g. /run/user/$UID/bus — the
// Secret Service / D-Bus session bus, KWallet, gpg-agent, legacy
// /tmp/dbus-*) survive the netns and would otherwise be mounted into
// the child by --ro-bind. The tmpfs masks below close that bypass.
// On all systemd distros /var/run is a symlink to /run, so masking
// /run/user also masks /var/run/user; do NOT add a second
// --tmpfs /var/run/user — bwrap fails with "Can't mkdir /var/run/user"
// when /var/run is a symlink to a now-empty tmpfs (see
// TestSandboxNet_TmpfsMasksDBus).
//
// J-12: audit log lives at $XDG_STATE_HOME/opq/ or $HOME/.local/state/opq/.
// Under --ro-bind / / the AI subprocess could cat audit.log and read
// caller="cli" entries (filterAuditLineForAI strips them for MCP audit_tail)
// plus raw_exit / elapsed_ms tokens (filterAuditMessageForAI strips them).
// Masking the audit directory with tmpfs closes that bypass. SandboxFull
// already tmpfs-masks /home so it is covered there incidentally.
func sandboxNetArgvCommon(auditDir string) []string {
	return []string{
		"--ro-bind", "/", "/",
		"--unshare-pid",
		"--proc", "/proc",
		"--tmpfs", "/dev/shm",
		"--tmpfs", "/run/user",
		"--tmpfs", "/tmp",
		"--tmpfs", auditDir,
		"--die-with-parent",
		"--new-session",
	}
}

// insertAfterRoBind inserts a single bwrap flag immediately after the
// `--ro-bind / /` pair at the head of the argv. Used to add
// --unshare-net to the shared SandboxNet/SandboxNetAllowed base while
// preserving the load-bearing left-to-right mount order described in
// sandboxNetArgvCommon. Panics if the head pair is not `--ro-bind /`
// — a structural invariant of sandboxNetArgvCommon, not a runtime
// condition; making it loud here catches a future refactor that breaks
// the assumption immediately rather than at sandbox-exec time.
func insertAfterRoBind(args []string, flag string) []string {
	if len(args) < 3 || args[0] != "--ro-bind" || args[1] != "/" || args[2] != "/" {
		panic(fmt.Sprintf("sandboxNetArgvCommon must start with --ro-bind / /, got %v", args))
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, args[:3]...)
	out = append(out, flag)
	out = append(out, args[3:]...)
	return out
}

// WrapCommand returns the argv to feed to exec.Command for running
// `cmd args...` under the chosen profile. For SandboxNone the call
// is a no-op passthrough. For SandboxNet / SandboxNetAllowed /
// SandboxFull, the command is resolved to an absolute path via PATH
// on the host first (bwrap then exec's that absolute path inside the
// sandbox — the host PATH lookup must happen before the FS view changes).
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
	case SandboxNet, SandboxNetAllowed:
		// Both profiles share the same filesystem sandbox (read-only host,
		// tmpfs masks on socket / tmp / dev-shm / audit-dir, private PID
		// namespace). They differ only in whether the netns is applied.
		//
		// SandboxNetAllowed exists because the previous v1.1.x design
		// routed allow_network=true to SandboxNone (no bwrap at all),
		// which let an AI write the resolved secret to /var/tmp/.x in
		// one call and `cat /var/tmp/.x` from a later SandboxNet call
		// (joint-review 2026-05 P2). Keeping the FS sandbox closes the
		// cross-call persistence vector while still letting the caller's
		// network-using command (curl, etc.) reach external hosts.
		auditDir, err := resolveAuditDirForMask()
		if err != nil {
			return "", nil, fmt.Errorf("resolve audit dir for sandbox mask: %w", err)
		}
		bwArgs = sandboxNetArgvCommon(auditDir)
		if profile == SandboxNet {
			// Inserted after --ro-bind / / (which is the first pair in the
			// common slice). Without --unshare-net the child has full host
			// network reachability; that's the SandboxNetAllowed contract.
			bwArgs = insertAfterRoBind(bwArgs, "--unshare-net")
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
