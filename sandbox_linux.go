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

// runtimeSocketDirs lists filesystem-path-reachable AF_UNIX socket
// DIRECTORIES that survive --unshare-net and (since they live under
// --ro-bind / /) are connect()-reachable from the sandboxed child.
// --ro-bind blocks WRITE, NOT connect(2). An AI under SandboxNet can
// curl --unix-socket <path> to invoke privileged APIs (Docker daemon,
// containerd, D-Bus -> Avahi mDNS, libvirt, etc.) and bypass the
// "never sees plaintext" property:
//
//   - P0-1 (Docker / LXD / Incus / podman group membership): a single
//     POST to /containers/create with -v /:/host yields arbitrary host
//     read; the AI cat's the secret out of the container's view of /.
//   - P1-2 (system D-Bus): Avahi typically permits unauthenticated
//     org.freedesktop.Avahi.EntryGroup.AddService -> AI publishes the
//     secret as an mDNS TXT record, broadcast to local LAN — defeats
//     --unshare-net entirely (the broadcast is the OPERATOR's network
//     stack handling the local-bus request).
//
// Each entry MUST be a directory (tmpfs cannot mount over a file).
// Entries are stat()'d at WrapCommand time because bwrap 0.11.0 has
// no --tmpfs-try and --tmpfs on a missing target fails "Can't mkdir".
// Only directories present on the host are masked; absent ones are
// silently skipped (TOCTOU: a runtime that appears between stat and
// exec is unmasked for that call only — the worst-case is the existing
// pre-fix state, never a stricter regression).
//
// Path policy: /run/X only, never /var/run/X. On systemd distros
// /var/run is a symlink to /run; once the parent /run/X is masked,
// bwrap fails to mkdir /var/run/X (same root cause as the J-1
// /var/run/user regression documented in TestSandboxNet_TmpfsMasksDBus).
var runtimeSocketDirs = []string{
	"/run/dbus",          // system D-Bus: Avahi mDNS exfil (P1-2) + other system services
	"/run/containerd",    // containerd CRI socket (kubernetes, nerdctl)
	"/run/crio",          // CRI-O socket (OpenShift / Kubernetes)
	"/run/podman",        // podman API socket
	"/run/k3s",           // k3s embedded containerd
	"/run/libvirt",       // libvirt / virtlogd: VM-escape vectors via qemu monitor
	"/run/lxd",           // LXD: lxd group -> privileged container -> -v /:/host (Kimi gate 1)
	"/run/incus",         // Incus (LXD fork): same primitive (Kimi gate 1)
	"/run/avahi-daemon",  // Avahi native protocol (D-Bus bypass, Kimi gate 1)
	"/run/buildkit",      // rootless BuildKit can build privileged images (Kimi gate 1)
}

// runtimeSocketFiles lists TOP-LEVEL AF_UNIX socket files that need
// individual masking because tmpfs cannot mount over a file (bwrap
// errors "Can't mkdir <socket>: Not a directory"). We use
// --bind /dev/null <path> to replace the socket with a character
// device that refuses connect().
//
// IMPORTANT: bwrap's --bind-try only skips when the SOURCE is missing
// (/dev/null is always present), NOT when the destination is missing —
// so --bind-try /dev/null /run/nonexistent.sock under --ro-bind / /
// fails with "Can't create file ... Read-only file system". We must
// stat each entry at WrapCommand time and only emit --bind if the
// destination exists. Verified directly against bwrap 0.11.0
// (Kimi gate 1).
var runtimeSocketFiles = []string{
	"/run/docker.sock",            // P0-1 primary: docker group -> -v /:/host -> arbitrary read
	"/run/snapd.socket",           // snapd: privesc via 'snap install' of a hook-bearing snap
	"/run/snapd-snap.socket",      // snapd control socket (Kimi gate 1)
	"/var/lib/lxd/unix.socket",    // LXD alt path on Debian/Ubuntu (Kimi gate 1)
	"/var/lib/incus/unix.socket",  // Incus alt path (Kimi gate 1)
}

// appendRuntimeSocketMasks appends --tmpfs and --bind entries for the
// container/system-bus sockets reachable via --ro-bind / /. Called
// after the static tmpfs masks so it preserves the load-bearing
// left-to-right ordering (anything appended here still post-dates
// --ro-bind / /). Indirected via os.Stat with a host-only view; in
// tests the slices are package-level vars but stat() runs against
// the real FS, which is the production behavior we want to lock down.
//
// Ordering within this function is also load-bearing: socket-file
// --bind entries are emitted BEFORE directory --tmpfs entries
// (Kimi gate 2 P1). The reverse order would crash bwrap if any future
// runtimeSocketFiles entry lives inside a runtimeSocketDirs entry —
// the tmpfs empties the parent and the subsequent --bind fails with
// ENOENT. Today the lists are disjoint, but keeping files-then-dirs
// is the defense against a future contributor adding e.g.
// /run/docker/docker.sock to the file list without realizing the
// /run/docker dir is being tmpfs'd ahead of it.
//
// Symlink handling: we use os.Stat (NOT Lstat) which follows
// symlinks. Two reasons (Kimi gate 2 P1):
//   - Linux mount(2) with MS_BIND follows DESTINATION symlinks, so a
//     symlinked entry in runtimeSocketFiles would have bwrap bind
//     /dev/null on the TARGET, not on the symlink — masking the wrong
//     path while leaving the original socket reachable via the link.
//     Using os.Stat at least guarantees the target exists; the actual
//     bypass mitigation is to keep runtimeSocketFiles pointed at the
//     canonical socket location and trust packagers to put it there.
//   - A dangling symlink passes Lstat but crashes bwrap (ENOENT on
//     the bind target). os.Stat fails on dangling symlinks, so the
//     skip path covers that case.
func appendRuntimeSocketMasks(args []string) []string {
	// Files first (see comment above on ordering).
	for _, path := range runtimeSocketFiles {
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		// Defense in depth: only mask if the target is actually a
		// socket. A regular file in /run with the same name would
		// suggest the host is in an unusual state; refuse to mask
		// rather than risk a spurious bind on the wrong inode kind.
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		args = append(args, "--bind", "/dev/null", path)
	}
	for _, dir := range runtimeSocketDirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		args = append(args, "--tmpfs", dir)
	}
	return args
}

// sandboxNetArgvCommon returns the bwrap argv shared by SandboxNet and
// SandboxNetAllowed. The two profiles differ only by whether the
// caller adds --unshare-net; everything else (read-only host bind,
// tmpfs masks on the socket/tmp/dev-shm/audit dirs, container-runtime
// socket masks, private PID namespace, --die-with-parent,
// --new-session) is identical.
//
// Ordering is load-bearing:
//   - --ro-bind / / must be FIRST so subsequent --tmpfs entries
//     shadow the host bind-mounts (bwrap applies mounts L→R).
//   - --proc /proc must come AFTER --ro-bind / / so it masks the host
//     procfs (PID-namespace isolation depends on this — finding C2).
//   - The runtime-socket masks appended by appendRuntimeSocketMasks
//     must come AFTER --ro-bind / / for the same shadowing reason.
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
//
// P0-1 / P1-2 (joint-review 2026-05 post-v1.1.3): the container-runtime
// AF_UNIX sockets (/run/docker.sock, /run/containerd, /run/podman, ...)
// and /run/dbus survive --unshare-net because --ro-bind blocks WRITE
// but not connect(2). The appendRuntimeSocketMasks call below closes
// these vectors. See runtimeSocketDirs / runtimeSocketFiles for the
// full list and per-entry rationale.
func sandboxNetArgvCommon(auditDir string) []string {
	args := []string{
		"--ro-bind", "/", "/",
		"--unshare-pid",
		"--proc", "/proc",
		"--tmpfs", "/dev/shm",
		"--tmpfs", "/run/user",
		"--tmpfs", "/tmp",
		"--tmpfs", auditDir,
	}
	args = appendRuntimeSocketMasks(args)
	args = append(args,
		"--die-with-parent",
		"--new-session",
	)
	return args
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
