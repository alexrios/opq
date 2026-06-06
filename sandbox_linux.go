//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// bwrapMinMajor / bwrapMinMinor: floor that supports all the flags
// we emit (--die-with-parent, --unshare-net, --new-session, --cap-drop).
// 0.5.0 is the earliest release that has the full set.
const (
	bwrapMinMajor = 0
	bwrapMinMinor = 5
)

// sandboxVerifyOnce / sandboxVerifyOnceErr cache the result of the
// (potentially fork-exec-heavy) sandbox availability probe for the life
// of the process. See VerifySandboxAvailable for the per-call cost
// motivation; see resetSandboxVerifyCacheForTest for the test hook.
var (
	sandboxVerifyOnce    sync.Once
	sandboxVerifyOnceErr error
)

// VerifySandboxAvailable returns nil if the non-None profiles will work here:
// bwrap on PATH at a sufficient version, and unprivileged user namespaces
// available (the kernel feature bwrap needs without setuid).
//
// The result — success or failure — is cached for the process lifetime. The
// probe is fork-exec-heavy (~10-50ms) and the host's bwrap/userns/AppArmor
// state is stable, so re-probing can't recover, only burn cycles. Operators who
// install bwrap mid-session must restart.
func VerifySandboxAvailable() error {
	sandboxVerifyOnce.Do(func() {
		sandboxVerifyOnceErr = verifySandboxAvailableUncached()
	})
	return sandboxVerifyOnceErr
}

// verifySandboxAvailableUncached performs the actual probe without
// any caching. Split out of VerifySandboxAvailable so the sync.Once
// wrapper stays trivial and so tests can drive the underlying logic
// after resetSandboxVerifyCacheForTest.
func verifySandboxAvailableUncached() error {
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
	// Functional probe: the version + sysctl checks are necessary but not
	// sufficient — an AppArmor profile on bwrap (Ubuntu 23.10+), seccomp, or a
	// missing CONFIG_USER_NS can still block namespace creation. Run a no-op
	// `true` under flags mirroring SandboxNet so a broken host fails here, at
	// startup, the same way a real call would.
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

// resetSandboxVerifyCacheForTest clears the sync.Once cache so a
// subsequent VerifySandboxAvailable call re-probes the host. Used by
// tests that manipulate PATH (e.g. faking bwrap missing) and rely on
// the next call observing the new environment. NOT for production code.
func resetSandboxVerifyCacheForTest() {
	sandboxVerifyOnce = sync.Once{}
	sandboxVerifyOnceErr = nil
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
	// Resolve symlinks so the tmpfs lands on the real inode (defense against
	// TOCTOU symlink swaps and future bwrap behavior changes).
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("evalsymlinks audit dir: %w", err)
	}
	return real, nil
}

// homeDirSocketTmpfsRel lists $HOME directories holding credential-agent
// AF_UNIX sockets. --ro-bind / / blocks writes but NOT connect(2), so without a
// tmpfs mask an AI under SandboxNet could connect() to e.g. gpg-agent and sign
// as the operator. Scope is intentionally narrow (canonical paths only); custom
// sockets elsewhere in $HOME need isolation="full".
//
// Masking $HOME/.gnupg breaks gpg running inside the sandbox — the correct
// trade: the sandbox is for arbitrary AI commands, not the operator's gpg keys.
var homeDirSocketTmpfsRel = []string{
	".gnupg", // gpg-agent socket family (S.gpg-agent, .ssh, .extra, .browser, .scdaemon)
}

// homeDirSocketFileRel lists $HOME AF_UNIX socket FILES. tmpfs can't mount over
// a file, so these are masked with --bind /dev/null, gated on existence + the
// ModeSocket bit (don't /dev/null a regular file at the same path).
var homeDirSocketFileRel = []string{
	".docker/run/docker.sock", // rootless Docker (Docker Desktop / rootlesskit)
}

// appendHomeDirSocketMasks masks the $HOME credential-agent sockets. $HOME is
// the operator's (os.UserHomeDir, parent env) — the AI can't influence it.
// Appended after the runtime-socket masks to preserve left-to-right shadowing.
// If $HOME is unset we fail OPEN (the broader /run masks still apply) rather
// than block every call on an environment opq already runs in.
func appendHomeDirSocketMasks(args []string) []string {
	home, err := homeDirForMask()
	if err != nil || home == "" {
		return args
	}
	// Files first, mirroring appendRuntimeSocketMasks: a future
	// contributor adding a file path inside one of the tmpfs dirs
	// would crash bwrap if tmpfs landed first. Today the lists are
	// disjoint but the ordering is defensive.
	for _, rel := range homeDirSocketFileRel {
		path := filepath.Join(home, rel)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		args = append(args, "--bind", "/dev/null", path)
	}
	for _, rel := range homeDirSocketTmpfsRel {
		path := filepath.Join(home, rel)
		st, err := os.Stat(path)
		if err != nil || !st.IsDir() {
			continue
		}
		args = append(args, "--tmpfs", path)
	}
	return args
}

// homeDirForMask returns the operator's $HOME for the purpose of
// building socket-mask paths. Indirected so tests can override without
// using t.Setenv on a process-global var (which would race with
// parallel tests). Production calls os.UserHomeDir.
var homeDirForMask = func() (string, error) {
	return os.UserHomeDir()
}

// runtimeSocketDirs lists AF_UNIX socket DIRECTORIES that survive --unshare-net
// (filesystem-reachable) and stay connect()-able under --ro-bind / / (which
// blocks write, not connect). Without these masks an AI can curl --unix-socket
// to a privileged API and bypass "never sees plaintext": e.g. the Docker daemon
// (-v /:/host -> arbitrary host read) or the system D-Bus -> Avahi mDNS
// (broadcast the secret on the LAN, defeating --unshare-net via the operator's
// own stack).
//
// Entries must be directories (tmpfs can't cover a file) and are stat()'d at
// wrap time (bwrap 0.11.0 --tmpfs fails on a missing target). /run/X only,
// never /var/run/X — on systemd /var/run symlinks to /run and double-masking
// crashes bwrap.
var runtimeSocketDirs = []string{
	"/run/dbus",         // system D-Bus: Avahi mDNS exfil + other system services
	"/run/containerd",   // containerd CRI socket (kubernetes, nerdctl)
	"/run/crio",         // CRI-O socket (OpenShift / Kubernetes)
	"/run/podman",       // podman API socket
	"/run/k3s",          // k3s embedded containerd
	"/run/libvirt",      // libvirt / virtlogd: VM-escape via qemu monitor
	"/run/lxd",          // LXD: lxd group -> privileged container -> -v /:/host
	"/run/incus",        // Incus (LXD fork): same primitive
	"/run/avahi-daemon", // Avahi native protocol (D-Bus bypass)
	"/run/buildkit",     // rootless BuildKit can build privileged images
}

// runtimeSocketFiles lists top-level AF_UNIX socket files masked individually
// with --bind /dev/null (tmpfs can't cover a file). bwrap's --bind-try only
// skips a missing SOURCE (/dev/null always exists), not a missing destination,
// so each entry is stat()'d at wrap time and bound only if it exists.
var runtimeSocketFiles = []string{
	"/run/docker.sock",           // docker group -> -v /:/host -> arbitrary read
	"/run/snapd.socket",          // snapd: privesc via 'snap install' of a hook-bearing snap
	"/run/snapd-snap.socket",     // snapd control socket
	"/var/lib/lxd/unix.socket",   // LXD alt path on Debian/Ubuntu
	"/var/lib/incus/unix.socket", // Incus alt path
}

// appendRuntimeSocketMasks masks the container/system-bus sockets reachable via
// --ro-bind / /. Two load-bearing details:
//   - Files (--bind) before dirs (--tmpfs): if a future socket file lived inside
//     a masked dir, tmpfs-first would empty the parent and the --bind would ENOENT.
//   - os.Stat (follows symlinks) so a dangling link is skipped rather than
//     crashing bwrap, and only real sockets are masked (the ModeSocket gate).
func appendRuntimeSocketMasks(args []string) []string {
	for _, path := range runtimeSocketFiles {
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
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

// sandboxNetArgvCommon is the bwrap argv shared by SandboxNet and
// SandboxNetAllowed; they differ only by --unshare-net (added by the caller).
//
// Ordering is load-bearing: --ro-bind / / must be FIRST so the --tmpfs masks
// below shadow the host bind, and --proc /proc must come after it.
//
// --unshare-net only blocks AF_INET/PACKET/NETLINK; AF_UNIX sockets reachable by
// path (the D-Bus session bus, container runtimes, gpg-agent, the audit log)
// survive it and would be exposed by --ro-bind / /. The masks here (plus
// appendRuntimeSocketMasks and appendHomeDirSocketMasks) close that; the
// audit-dir mask also stops the child reading caller="cli" entries the MCP
// filters hide. Don't add --tmpfs /var/run/user — /var/run symlinks to /run, so
// masking /run/user covers it and double-masking crashes bwrap.
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
	args = appendHomeDirSocketMasks(args)
	args = append(args,
		"--die-with-parent",
		"--new-session",
	)
	return args
}

// insertAfterRoBind inserts a flag right after the leading `--ro-bind / /` pair,
// preserving the mount order sandboxNetArgvCommon depends on. Panics if that
// pair isn't at the head — a structural invariant, loud here so a future
// refactor breaks at build/test time, not at sandbox-exec time.
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

// WrapCommand returns the argv to run `cmd args...` under the given profile.
// SandboxNone is a passthrough. Otherwise cmd is resolved to an absolute path on
// the HOST first — the PATH lookup must precede the sandbox's FS view change.
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
		// Both share the FS sandbox; they differ only by the netns.
		// SandboxNetAllowed keeps the FS sandbox (rather than no bwrap) so an AI
		// can't persist the secret to a host path in a network-allowed call and
		// read it back from a later sandboxed one.
		auditDir, err := resolveAuditDirForMask()
		if err != nil {
			return "", nil, fmt.Errorf("resolve audit dir for sandbox mask: %w", err)
		}
		bwArgs = sandboxNetArgvCommon(auditDir)
		if profile == SandboxNet {
			// SandboxNet adds the netns; without it (SandboxNetAllowed) the
			// child keeps host network reachability.
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
