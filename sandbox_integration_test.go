//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func runUnderSandbox(t *testing.T, profile SandboxProfile, cmd string, args ...string) (string, int, error) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	wrapCmd, wrapArgs, err := WrapCommand(profile, cmd, args)
	if err != nil {
		return "", -1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, wrapCmd, wrapArgs...)
	c.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	runErr := c.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return buf.String(), code, nil
}

func hasInternet(t *testing.T) bool {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func TestSandboxNet_BlocksNetwork(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxNet, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "3",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code == 0 {
		t.Fatalf("expected curl to fail under SandboxNet, code=0 out=%q", out)
	}
	if strings.Contains(out, "200") {
		t.Fatalf("response 200 leaked through sandbox: %q", out)
	}
}

func TestSandboxNet_AllowsHostFS(t *testing.T) {
	out, code, err := runUnderSandbox(t, SandboxNet, "cat", "/etc/hostname")
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code != 0 {
		t.Fatalf("cat /etc/hostname under SandboxNet failed (code=%d): %q", code, out)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("empty hostname output: %q", out)
	}
}

// TestSandboxNet_BlocksHostFSWrite (P0-1): SandboxNet must prevent the AI
// subprocess from writing to any persistent host path (e.g. /var/tmp).
// Without this, a two-call exfil chain works: call 1 writes the secret to
// /var/tmp/.leak, call 2 reads it back with an empty env (no redaction).
// The fix is --ro-bind / / instead of --dev-bind / /.
func TestSandboxNet_BlocksHostFSWrite(t *testing.T) {
	out, code, err := runUnderSandbox(t, SandboxNet, "sh", "-c", "touch /var/tmp/opq_p01_test 2>&1")
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	// touch must fail because the host FS is read-only.
	if code == 0 {
		t.Fatalf("write to /var/tmp succeeded under SandboxNet (P0-1 regression): %q", out)
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "read-only") && !strings.Contains(lower, "permission denied") && !strings.Contains(lower, "no such") {
		t.Errorf("expected read-only or permission error, got: %q", out)
	}
}

func TestSandboxFull_BlocksNetwork(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxFull, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "3",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code == 0 {
		t.Fatalf("expected curl to fail under SandboxFull, code=0 out=%q", out)
	}
	if strings.Contains(out, "200") {
		t.Fatalf("response 200 leaked through sandbox: %q", out)
	}
}

func TestSandboxFull_BlocksHomeRead(t *testing.T) {
	user := os.Getenv("USER")
	if user == "" {
		t.Skip("USER unset")
	}
	target := "/home/" + user + "/.ssh"
	out, code, err := runUnderSandbox(t, SandboxFull, "ls", target)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	// Either the directory is missing (tmpfs overlay) or ls fails;
	// either way the host's real .ssh contents must not appear.
	if code == 0 && strings.Contains(out, "id_") {
		t.Fatalf("SandboxFull leaked $HOME/.ssh contents: %q", out)
	}
}

func TestSandboxNone_AllowsNetwork(t *testing.T) {
	if !hasInternet(t) {
		t.Skip("no internet")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxNone, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "5",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected curl to succeed without sandbox, code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "200") && !strings.Contains(out, "301") && !strings.Contains(out, "302") {
		t.Fatalf("expected HTTP response from 1.1.1.1, got %q", out)
	}
}

// TestSandboxNet_DBusUnreachable (J-1): the SandboxNet tmpfs masks on
// /run/user and /tmp must hide the D-Bus session bus socket and other
// filesystem-path Unix sockets that --unshare-net does NOT block. On
// systemd distros /var/run is a symlink to /run, so masking /run/user
// also masks /var/run/user. We attempt to stat /run/user/$(id -u)/bus
// from inside the sandbox; either the directory is missing (tmpfs is
// empty) or the file is absent; either way, the child must not be able
// to reach the host's keyring/D-Bus socket. Same check for /tmp.
func TestSandboxNet_DBusUnreachable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}

	// One sh invocation, two checks. We test for the .../bus socket and
	// also for any contents in /tmp. The UID is resolved on the host (not
	// inside the sandbox via $(id -u)) so the test still functions on
	// stripped environments where /usr/bin/id is missing; otherwise the
	// substituted path becomes /run/user//bus and ls fails with ENOENT
	// regardless of whether the mask is working. The script always exits
	// 0; the test inspects the combined output.
	uid := os.Getuid()
	out, _, err := runUnderSandbox(t, SandboxNet, "sh", "-c",
		fmt.Sprintf("ls -A /run/user/%d/bus 2>&1; echo ---; ls -A /tmp 2>&1", uid),
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	// Host-side bwrap setup failure (e.g. a symlinked mount path that
	// can't be mkdir'd after a tmpfs mask) prints "bwrap: ..." and never
	// reaches our `---` divider. This is the exact failure mode of the
	// /var/run/user regression J-1 originally shipped with, so failing
	// loudly here is the regression guard; do NOT skip.
	if strings.HasPrefix(strings.TrimSpace(out), "bwrap:") {
		t.Fatalf("bwrap setup failed under SandboxNet (likely a J-1 regression, tmpfs mask broke the mount layout): %q", out)
	}
	parts := strings.SplitN(out, "---", 2)
	if len(parts) != 2 {
		t.Fatalf("expected '---' divider in output, got: %q", out)
	}
	busOut := strings.TrimSpace(parts[0])
	tmpOut := strings.TrimSpace(parts[1])
	// The D-Bus socket path must be unreachable. Accept any of:
	//   "No such file or directory"
	//   "ls: cannot access ..." (busybox)
	//   empty (directory doesn't exist; some sh versions swallow the err)
	if strings.Contains(busOut, "/bus") && !strings.Contains(strings.ToLower(busOut), "no such") &&
		!strings.Contains(strings.ToLower(busOut), "cannot") {
		// A bare "/run/user/<uid>/bus" line in output without a
		// "no such"/"cannot" error indicates the socket survived the tmpfs.
		t.Errorf("D-Bus socket appears reachable under SandboxNet: %q", busOut)
	}
	// /tmp must be an empty tmpfs (ls -A on empty dir prints nothing).
	if tmpOut != "" {
		t.Errorf("/tmp not empty under SandboxNet (cross-call channel open): %q", tmpOut)
	}
}

// TestSandboxNet_AuditLogUnreachable (J-12 regression): SandboxNet must
// tmpfs-mask the audit directory so an AI subprocess under
// run_with_secrets cannot bypass filterAuditLineForAI /
// filterAuditMessageForAI by `cat`ing audit.log directly. We set
// XDG_STATE_HOME to a fresh tmpdir, plant a canary line in
// <tmp>/opq/audit.log on the host, then attempt to read it from inside
// the sandbox. The canary must NOT appear in the child's output, and the
// tmpfs-masked directory must be empty (or the read must fail outright).
func TestSandboxNet_AuditLogUnreachable(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)

	const canary = "CANARY_J12_AUDIT_LOG_CONTENT"
	auditDir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	logPath := filepath.Join(auditDir, "audit.log")
	if err := os.WriteFile(logPath, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatalf("plant canary: %v", err)
	}

	// The audit dir under WrapCommand goes through filepath.EvalSymlinks.
	// On macOS /tmp -> /private/tmp; on Linux t.TempDir() is typically
	// already canonical but resolve anyway for robustness.
	canonDir := auditDir
	if resolved, err := filepath.EvalSymlinks(auditDir); err == nil {
		canonDir = resolved
	}

	// Hand the canonical absolute path to the inner shell. runUnderSandbox
	// sets the child env to a minimal {PATH, HOME=/tmp} and does NOT
	// forward XDG_STATE_HOME, so `$XDG_STATE_HOME` would expand to empty
	// in the child. Using the literal path keeps the test focused on the
	// tmpfs mask, not on env propagation.
	//
	// Kimi P0: also exercise /proc/self/root/<auditPath>; a broken PID
	// or mount namespace could leave /proc/self/root pointing to the
	// pre-mask host view. With --unshare-pid + --proc /proc this should
	// resolve to the sandboxed FS, so the cat must fail or return empty.
	script := "cat " + canonDir + "/audit.log 2>&1; echo ---; " +
		"ls -A " + canonDir + " 2>&1; echo ---; " +
		"cat /proc/self/root" + canonDir + "/audit.log 2>&1"
	out, _, err := runUnderSandbox(t, SandboxNet, "sh", "-c", script)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	// bwrap setup failure (e.g. missing dir target) would surface as
	// "bwrap: ..." before the script runs; that is itself a regression of
	// the audit-dir resolver, so fail loudly rather than skip.
	if strings.HasPrefix(strings.TrimSpace(out), "bwrap:") {
		t.Fatalf("bwrap setup failed under SandboxNet (J-12 regression, audit-dir tmpfs broke mount layout): %q", out)
	}
	if strings.Contains(out, canary) {
		t.Fatalf("J-12 regression: canary %q reachable inside SandboxNet:\n%s", canary, out)
	}
	parts := strings.SplitN(out, "---", 3)
	if len(parts) != 3 {
		t.Fatalf("expected two '---' dividers in output, got: %q", out)
	}
	lsOut := strings.TrimSpace(parts[1])
	procRootOut := strings.TrimSpace(parts[2])
	// Accept either: empty tmpfs (ls -A prints nothing) OR a "no such
	// file" error. A non-empty listing means the host directory survived
	// the mask.
	lower := strings.ToLower(lsOut)
	if lsOut != "" &&
		!strings.Contains(lower, "no such") &&
		!strings.Contains(lower, "cannot access") {
		t.Errorf("audit dir not masked under SandboxNet (expected empty tmpfs or ENOENT, got %q)", lsOut)
	}
	// /proc/self/root escape: must not surface the canary either.
	if strings.Contains(procRootOut, canary) {
		t.Fatalf("J-12 /proc/self/root escape: canary reachable via /proc/self/root%s/audit.log:\n%s",
			canonDir, procRootOut)
	}
}

// TestSandboxNet_DockerSocketUnreachable (P0-1): when the host has
// /run/docker.sock, the SandboxNet child must NOT be able to connect()
// to it. --ro-bind / / blocks WRITE but not connect(); without the
// --bind /dev/null /run/docker.sock mask, an AI under run_with_secrets
// can `curl --unix-socket /var/run/docker.sock http://localhost/containers/create`
// and (with operator in docker group) get a privileged container with
// -v /:/host, defeating "never sees plaintext".
//
// The mask replaces the socket file with /dev/null, which is a character
// device that refuses connect(2). Inside the sandbox the inode is a
// character device, not a socket; the simplest check is `test -S` which
// must report "not a socket".
func TestSandboxNet_DockerSocketUnreachable(t *testing.T) {
	if _, err := os.Lstat("/run/docker.sock"); err != nil {
		t.Skip("host has no /run/docker.sock; nothing to mask")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	out, _, err := runUnderSandbox(t, SandboxNet, "sh", "-c",
		// Three probes: socket-type, character-device-type (expected after
		// --bind /dev/null), and a connect() attempt via /dev/tcp-style is
		// not possible for AF_UNIX from POSIX sh, so we rely on the inode
		// type change as the load-bearing signal.
		"if [ -S /run/docker.sock ]; then echo SOCKET; "+
			"elif [ -c /run/docker.sock ]; then echo CHARDEV; "+
			"elif [ ! -e /run/docker.sock ]; then echo MISSING; "+
			"else echo OTHER; fi",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "bwrap:") {
		t.Fatalf("bwrap setup failed (regression in socket-file masking): %q", out)
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "SOCKET" {
		t.Fatalf("P0-1 regression: /run/docker.sock still reachable as AF_UNIX socket inside SandboxNet: %q", out)
	}
	// MISSING also acceptable (some bwrap versions delete the inode under
	// the tmpfs view); CHARDEV is the expected case for --bind /dev/null.
	if trimmed != "CHARDEV" && trimmed != "MISSING" {
		t.Errorf("expected docker.sock masked to /dev/null (CHARDEV) or removed (MISSING), got %q", out)
	}
}

// TestSandboxNet_SystemDBusUnreachable (P1-2): when the host has
// /run/dbus/system_bus_socket, the SandboxNet child must NOT be able
// to connect() to it. Without the --tmpfs /run/dbus mask, an AI under
// run_with_secrets can talk to Avahi (org.freedesktop.Avahi.EntryGroup.AddService
// typically permits unauthenticated publishing) and broadcast the secret
// as an mDNS TXT record on the local LAN; defeats --unshare-net entirely
// because the broadcast happens via the host's network stack handling
// the LOCAL-BUS request.
//
// Under --tmpfs /run/dbus, the parent directory becomes an empty tmpfs
// and the system_bus_socket disappears from the child's view.
func TestSandboxNet_SystemDBusUnreachable(t *testing.T) {
	if _, err := os.Lstat("/run/dbus/system_bus_socket"); err != nil {
		t.Skip("host has no /run/dbus/system_bus_socket; nothing to mask")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	// We cannot redirect to /dev/null inside the sandbox: under --ro-bind / /,
	// sh's redirection opens the file with O_WRONLY on a read-only-mounted
	// /dev, which the kernel rejects with EACCES ("cannot create /dev/null:
	// Permission denied"). Use a tempfile in /tmp (tmpfs, writable) or do
	// without; here we use the existence-only check to avoid the
	// redirection entirely.
	out, _, err := runUnderSandbox(t, SandboxNet, "sh", "-c",
		"if [ -S /run/dbus/system_bus_socket ]; then echo SOCKET; "+
			"elif [ ! -e /run/dbus/system_bus_socket ]; then echo MISSING_OR_MASKED; "+
			"else echo OTHER; fi",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "bwrap:") {
		t.Fatalf("bwrap setup failed (regression in /run/dbus masking): %q", out)
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "SOCKET" {
		t.Fatalf("P1-2 regression: /run/dbus/system_bus_socket still reachable inside SandboxNet: %q", out)
	}
	if trimmed != "MISSING_OR_MASKED" {
		t.Errorf("expected /run/dbus/system_bus_socket masked or missing, got %q", out)
	}
}

// TestSandboxNet_FakeSocketMaskTechnique (Kimi gate 1): proves the
// --bind /dev/null technique actually defeats connect() on a freshly
// created Unix socket, independent of which container runtimes are
// installed on the host. This is the technique-verification test:
// even on CI runners with no Docker / no D-Bus, we still execute the
// load-bearing mount semantics and confirm a real AF_UNIX listener
// becomes unreachable after the mask.
//
// We construct a custom bwrap argv (rather than going through
// WrapCommand) because the production runtimeSocketFiles list is
// path-pinned; the test needs a fresh socket in t.TempDir() to avoid
// host interference. The mask shape (--bind /dev/null <path>) is the
// same one production emits in appendRuntimeSocketMasks.
func TestSandboxNet_FakeSocketMaskTechnique(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "fake.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatalf("bwrap lookup: %v", err)
	}
	bwArgs := []string{
		"--ro-bind", "/", "/",
		"--bind", "/dev/null", sockPath,
		"--unshare-net", "--unshare-pid",
		"--proc", "/proc",
		"--die-with-parent", "--new-session",
		"--", "/bin/sh", "-c",
		"if [ -S " + sockPath + " ]; then echo SOCKET; " +
			"elif [ -c " + sockPath + " ]; then echo CHARDEV; " +
			"elif [ ! -e " + sockPath + " ]; then echo MISSING; " +
			"else echo OTHER; fi",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrapBin, bwArgs...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()
	got := strings.TrimSpace(buf.String())
	if strings.HasPrefix(got, "bwrap:") {
		t.Fatalf("bwrap setup failed: %q", got)
	}
	if got == "SOCKET" {
		t.Fatalf("--bind /dev/null technique failed: socket still AF_UNIX after mask: %q", got)
	}
	if got != "CHARDEV" {
		t.Errorf("expected mask to replace socket with chardev (/dev/null), got %q", got)
	}
}

// TestSandboxNet_FakeTmpfsMaskTechnique (Kimi gate 2 P2): the
// FakeSocketMaskTechnique test above only proves the --bind /dev/null
// technique works on socket files. The --tmpfs technique for
// directory masking is the other half of appendRuntimeSocketMasks and
// is not exercised end-to-end if a bare CI runner has no Docker /
// no D-Bus (both per-runtime integration tests skip in that case).
// This test constructs a fresh directory in t.TempDir() containing a
// real Unix socket, then runs bwrap with `--tmpfs <dir>` and verifies
// the socket disappears from the child's view. Independent of host
// state.
func TestSandboxNet_FakeTmpfsMaskTechnique(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	root := t.TempDir()
	maskDir := filepath.Join(root, "sockdir")
	if err := os.Mkdir(maskDir, 0o755); err != nil {
		t.Fatalf("mkdir maskDir: %v", err)
	}
	sockPath := filepath.Join(maskDir, "svc.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	// Sanity: confirm the socket is reachable from the host before we mask.
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("pre-mask stat sockPath: %v", err)
	}

	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatalf("bwrap lookup: %v", err)
	}
	bwArgs := []string{
		"--ro-bind", "/", "/",
		"--tmpfs", maskDir,
		"--unshare-net", "--unshare-pid",
		"--proc", "/proc",
		"--die-with-parent", "--new-session",
		"--", "/bin/sh", "-c",
		// EMPTY_DIR is the expected case (tmpfs hides original contents).
		// MISSING_DIR would also be acceptable but should not happen because
		// --tmpfs requires the target dir to exist.
		"if [ -S " + sockPath + " ]; then echo SOCKET_REACHABLE; " +
			"elif [ ! -e " + sockPath + " ]; then echo SOCKET_MASKED; " +
			"else echo OTHER; fi",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bwrapBin, bwArgs...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()
	got := strings.TrimSpace(buf.String())
	if strings.HasPrefix(got, "bwrap:") {
		t.Fatalf("bwrap setup failed: %q", got)
	}
	if got == "SOCKET_REACHABLE" {
		t.Fatalf("--tmpfs technique failed: socket still reachable inside masked dir: %q", got)
	}
	if got != "SOCKET_MASKED" {
		t.Errorf("expected --tmpfs to hide socket (SOCKET_MASKED), got %q", got)
	}
}

// TestSandboxNet_SiblingProcIsolation verifies fix for finding C2 (v1.1.1 security review):
// a sibling SandboxNet subprocess must not be able to read another sibling's
// /proc/<pid>/environ (which would expose injected secrets).
//
// Strategy: launch subprocess A (sleep 30) under SandboxNet, confirm it is still alive,
// then launch subprocess B that attempts to grep /proc/*/environ for a canary value.
// B must not find A's environ.
func TestSandboxNet_SiblingProcIsolation(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	if _, err := exec.LookPath("grep"); err != nil {
		t.Skip("grep not available")
	}

	// Canary value that subprocess A will carry in its environment.
	// We deliberately do NOT put this in the test process's env, so any match
	// in B's output means cross-namespace /proc leakage.
	const canary = "OPQ_C2_CANARY_32chars_unique_value"

	// Build argv for A: sleep long enough for B to run its grep.
	wrapCmdA, wrapArgsA, err := WrapCommand(SandboxNet, "sh", []string{"-c", "sleep 30"})
	if err != nil {
		t.Fatalf("WrapCommand A: %v", err)
	}

	// Build argv for B: grep all /proc/*/environ for the canary.
	// B runs with a clean env (no canary), so a hit means it read A's env.
	wrapCmdB, wrapArgsB, err := WrapCommand(SandboxNet, "sh", []string{"-c",
		fmt.Sprintf("grep -rl '%s' /proc/*/environ 2>/dev/null || true", canary),
	})
	if err != nil {
		t.Fatalf("WrapCommand B: %v", err)
	}

	// Start A with the canary in its env.
	ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelA()
	cmdA := exec.CommandContext(ctxA, wrapCmdA, wrapArgsA...)
	cmdA.Env = []string{
		"PATH=/usr/bin:/usr/sbin:/bin:/sbin",
		"HOME=/tmp",
		canary + "=supersecretvalue",
	}
	if err := cmdA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill(); _ = cmdA.Wait() }()

	// Give A time to settle in its sandbox.
	time.Sleep(500 * time.Millisecond)
	// Verify A is still running. cmd.ProcessState is only populated after
	// Wait() returns, so cannot be used here; signal 0 on a live pid is a
	// no-op that returns nil, on a dead pid it returns ESRCH. A live A is
	// load-bearing for this test: without it, B's "canary not found in
	// /proc" would pass vacuously because A's environ has already
	// disappeared.
	if err := cmdA.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("subprocess A is not alive (signal 0 failed: %v); isolation not tested", err)
	}

	// Run B and collect output.
	var wg sync.WaitGroup
	var outB string
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctxB, cancelB := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelB()
		cmdB := exec.CommandContext(ctxB, wrapCmdB, wrapArgsB...)
		cmdB.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
		var buf bytes.Buffer
		cmdB.Stdout = &buf
		cmdB.Stderr = &buf
		_ = cmdB.Run()
		outB = buf.String()
	}()
	wg.Wait()

	if strings.Contains(outB, canary) {
		t.Errorf("SandboxNet sibling /proc leakage: subprocess B found canary in output:\n%s", outB)
	}
}
