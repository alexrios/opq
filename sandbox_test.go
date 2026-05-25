package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWrapCommand_SandboxNone(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		args []string
	}{
		{"no args", "/bin/true", nil},
		{"with args", "/bin/sh", []string{"-c", "echo hi"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCmd, gotArgs, err := WrapCommand(SandboxNone, c.cmd, c.args)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if gotCmd != c.cmd {
				t.Errorf("cmd = %q, want %q", gotCmd, c.cmd)
			}
			if !slicesEqual(gotArgs, c.args) {
				t.Errorf("args = %v, want %v", gotArgs, c.args)
			}
		})
	}
}

func TestWrapCommand_SandboxNet_BwrapArgv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	gotCmd, gotArgs, err := WrapCommand(SandboxNet, "true", []string{"arg1"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if filepath.Base(gotCmd) != "bwrap" {
		t.Errorf("wrapper cmd = %q, want bwrap", gotCmd)
	}
	// C2 fix: SandboxNet must include PID namespace isolation and private /proc
	// to prevent sibling run_with_secrets calls from reading each other's
	// /proc/<pid>/environ (finding C2 from the v1.1.1 security review).
	for _, want := range []string{"--unshare-net", "--unshare-pid", "--dev-bind", "--die-with-parent", "--new-session"} {
		if !containsArg(gotArgs, want) {
			t.Errorf("net argv missing %q: %v", want, gotArgs)
		}
	}
	// --proc /proc must appear as a sequence (private procfs for PID namespace).
	if !hasSeq(gotArgs, []string{"--proc", "/proc"}) {
		t.Errorf("net argv missing '--proc /proc' sequence: %v", gotArgs)
	}
	// --proc /proc must come AFTER --dev-bind / / so it masks the host procfs.
	// bwrap applies mounts left-to-right; reversing this defeats PID ns isolation.
	devBindIdx := indexOf(gotArgs, "--dev-bind")
	procIdx := indexOf(gotArgs, "--proc")
	if devBindIdx < 0 || procIdx < 0 {
		t.Errorf("argv missing --dev-bind or --proc: %v", gotArgs)
	} else if procIdx < devBindIdx {
		t.Errorf("--proc (idx %d) must come after --dev-bind (idx %d) in argv: %v", procIdx, devBindIdx, gotArgs)
	}
	// The command must be resolved to an absolute path before the `--`
	// terminator, since bwrap exec's it inside the sandbox.
	dashIdx := indexOf(gotArgs, "--")
	if dashIdx < 0 {
		t.Fatalf("missing -- terminator in %v", gotArgs)
	}
	if dashIdx+1 >= len(gotArgs) {
		t.Fatalf("no command after -- in %v", gotArgs)
	}
	resolved := gotArgs[dashIdx+1]
	if !filepath.IsAbs(resolved) {
		t.Errorf("command after -- must be absolute, got %q", resolved)
	}
}

// TestSandboxNet_TmpfsMasksDBus (J-1) — the SandboxNet argv must mask
// the standard Unix-socket directories (/run/user, /tmp) with tmpfs so
// the child cannot reach the D-Bus / Secret Service / KWallet /
// gpg-agent sockets that the netns alone does NOT block. We deliberately
// do NOT mask /var/run/user separately — on all systemd distros it is a
// symlink to /run/user, and masking the symlink target after the parent
// /var/run path becomes a stale symlink causes bwrap to fail with
// "Can't mkdir /var/run/user". Each tmpfs sequence must appear AFTER
// --dev-bind / / so it shadows the host bind-mount (bwrap applies mounts
// left-to-right).
func TestSandboxNet_TmpfsMasksDBus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	maskedDirs := []string{"/run/user", "/tmp"}
	devBindIdx := indexOf(gotArgs, "--dev-bind")
	if devBindIdx < 0 {
		t.Fatalf("--dev-bind missing from SandboxNet argv: %v", gotArgs)
	}
	for _, dir := range maskedDirs {
		if !hasSeq(gotArgs, []string{"--tmpfs", dir}) {
			t.Errorf("SandboxNet argv missing '--tmpfs %s' mask: %v", dir, gotArgs)
			continue
		}
		// The tmpfs must come AFTER --dev-bind / /. Find the --tmpfs <dir>
		// pair and assert the --tmpfs token sits past the dev-bind index.
		for i := 0; i+1 < len(gotArgs); i++ {
			if gotArgs[i] == "--tmpfs" && gotArgs[i+1] == dir {
				if i < devBindIdx {
					t.Errorf("--tmpfs %s (idx %d) must come AFTER --dev-bind (idx %d): %v",
						dir, i, devBindIdx, gotArgs)
				}
				break
			}
		}
	}
	// Forbidden masks: re-introducing --tmpfs /var/run/user breaks bwrap on
	// every systemd distro because /var/run is a symlink to /run; after
	// --tmpfs /run/user empties the target, bwrap cannot mkdir
	// /var/run/user inside the now-empty tmpfs. Guard against the
	// regression with an explicit negative assertion.
	if hasSeq(gotArgs, []string{"--tmpfs", "/var/run/user"}) {
		t.Errorf("SandboxNet argv must NOT mask /var/run/user (the /var/run -> /run symlink covers it; explicit mask breaks bwrap): %v", gotArgs)
	}
}

func TestWrapCommand_SandboxFull_BwrapArgv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	_, gotArgs, err := WrapCommand(SandboxFull, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantFlags := []string{"--unshare-all", "--tmpfs", "--cap-drop", "ALL"}
	for _, want := range wantFlags {
		if !containsArg(gotArgs, want) {
			t.Errorf("full argv missing %q: %v", want, gotArgs)
		}
	}
	// --ro-bind /usr /usr must appear as a sequence.
	if !hasSeq(gotArgs, []string{"--ro-bind", "/usr", "/usr"}) {
		t.Errorf("full argv missing '--ro-bind /usr /usr': %v", gotArgs)
	}
	if !hasSeq(gotArgs, []string{"--tmpfs", "/home"}) {
		t.Errorf("full argv missing '--tmpfs /home': %v", gotArgs)
	}
}

func TestVerifySandboxAvailable_OK(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatalf("VerifySandboxAvailable: %v", err)
	}
}

func TestVerifySandboxAvailable_BwrapMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	empty := t.TempDir()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", empty)
	defer t.Setenv("PATH", orig)

	err := VerifySandboxAvailable()
	if err == nil {
		t.Fatalf("expected error when bwrap is unreachable")
	}
	msg := err.Error()
	for _, want := range []string{"bubblewrap", "apt", "dnf", "pacman"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing install hint %q: %s", want, msg)
		}
	}
}

// TestVerifySandboxAvailable_ProbeFailsWhenBwrapBroken (J-9) — a host
// where bwrap reports a healthy version but cannot actually create
// namespaces (e.g. AppArmor profile blocks unshare) must surface the
// failure at startup rather than as obscure run_with_secrets failures
// later. We simulate by planting a fake bwrap on PATH that prints the
// expected version string for --version and exits 1 on any other argv
// (i.e. the namespace-probe invocation).
func TestVerifySandboxAvailable_ProbeFailsWhenBwrapBroken(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("/bin/sh required")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "bwrap")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  --version) echo 'bubblewrap 0.11.0'; exit 0;;\n" +
		"  *) echo 'fake bwrap: setting up user namespace: Operation not permitted' 1>&2; exit 1;;\n" +
		"esac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake bwrap: %v", err)
	}
	t.Setenv("PATH", dir)

	err := VerifySandboxAvailable()
	if err == nil {
		t.Fatalf("expected probe error when bwrap exits 1 on namespace flags")
	}
	if !strings.Contains(err.Error(), "namespace probe") {
		t.Errorf("expected error to mention 'namespace probe', got: %v", err)
	}
}

func TestResolveMCPSandbox(t *testing.T) {
	cases := []struct {
		name         string
		allowNetwork bool
		isolation    string
		want         SandboxProfile
		wantErr      bool
	}{
		{"defaults", false, "", SandboxNet, false},
		{"net explicit", false, "net", SandboxNet, false},
		{"full", false, "full", SandboxFull, false},
		{"allow_network default", true, "", SandboxNone, false},
		{"allow_network + net", true, "net", SandboxNone, false},
		{"allow_network + full rejected", true, "full", SandboxNone, true},
		{"unknown isolation", false, "bogus", SandboxNone, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveMCPSandbox(c.allowNetwork, c.isolation)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseSandboxFlag(t *testing.T) {
	cases := []struct {
		in      string
		want    SandboxProfile
		wantErr bool
	}{
		{"", SandboxNone, false},
		{"none", SandboxNone, false},
		{"net", SandboxNet, false},
		{"full", SandboxFull, false},
		{"bogus", SandboxNone, true},
	}
	for _, c := range cases {
		got, err := parseSandboxFlag(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseSandboxFlag(%q) err = %v, wantErr=%v", c.in, err, c.wantErr)
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parseSandboxFlag(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// SandboxNet tmpfs-masks the audit directory (J-12 / P0-2).
//
// Background: under SandboxNet, --dev-bind / / makes the host filesystem
// visible to the child. Without an explicit mask, the AI-spawned subprocess
// could read $XDG_STATE_HOME/opq/audit.log (or the HOME fallback) and recover
// raw_exit / elapsed_ms tokens that filterAuditMessageForAI strips from the
// MCP audit_tail response. The fix in sandbox_linux.go appends
// `--tmpfs <auditDir>` to the SandboxNet argv. These tests lock down:
//   - the argv includes the tmpfs after --dev-bind / /
//   - the HOME fallback works when XDG_STATE_HOME is unset
//   - the wrapper fails CLOSED (no argv produced) if neither path resolves
//   - SandboxFull does NOT reach the audit-dir resolver (it tmpfs-masks /home
//     wholesale, so the resolver must not be a hard dependency there)
// -----------------------------------------------------------------------------

// TestSandboxNet_TmpfsMasksAuditDir locks the canonical XDG_STATE_HOME path.
// With XDG_STATE_HOME=<tmp>, the resolved audit dir is <tmp>/opq and the
// argv must carry "--tmpfs <tmp>/opq" after --dev-bind / /.
func TestSandboxNet_TmpfsMasksAuditDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)

	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}

	wantDir := filepath.Join(tmp, "opq")
	// EvalSymlinks resolves /tmp -> /private/tmp on macOS, but we already
	// skipped non-linux above. On linux, t.TempDir under /tmp may already be
	// canonical; if not, mirror resolveAuditDirForMask's EvalSymlinks step.
	if resolved, err := filepath.EvalSymlinks(wantDir); err == nil {
		wantDir = resolved
	}

	if !hasSeq(gotArgs, []string{"--tmpfs", wantDir}) {
		t.Fatalf("SandboxNet argv missing '--tmpfs %s': %v", wantDir, gotArgs)
	}
	devBindIdx := indexOf(gotArgs, "--dev-bind")
	if devBindIdx < 0 {
		t.Fatalf("--dev-bind missing from SandboxNet argv: %v", gotArgs)
	}
	// The audit-dir tmpfs must come AFTER --dev-bind / / so it shadows the
	// inherited bind-mount (bwrap applies left-to-right).
	for i := 0; i+1 < len(gotArgs); i++ {
		if gotArgs[i] == "--tmpfs" && gotArgs[i+1] == wantDir {
			if i < devBindIdx {
				t.Errorf("--tmpfs %s (idx %d) must come AFTER --dev-bind (idx %d): %v",
					wantDir, i, devBindIdx, gotArgs)
			}
			return
		}
	}
}

// TestSandboxNet_TmpfsMasksAuditDir_HonorsHomeFallback covers the second
// auditLogPath branch: when XDG_STATE_HOME is empty, the audit dir is
// $HOME/.local/state/opq. The argv must carry that path as a tmpfs mask.
func TestSandboxNet_TmpfsMasksAuditDir_HonorsHomeFallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	home := t.TempDir()
	// Explicitly clear XDG_STATE_HOME so auditLogPath falls back to HOME.
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", home)

	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}

	wantDir := filepath.Join(home, ".local", "state", "opq")
	if resolved, err := filepath.EvalSymlinks(wantDir); err == nil {
		wantDir = resolved
	}

	if !hasSeq(gotArgs, []string{"--tmpfs", wantDir}) {
		t.Errorf("SandboxNet argv missing '--tmpfs %s' from HOME fallback: %v", wantDir, gotArgs)
	}
}

// TestSandboxNet_FailsClosedOnUnresolvableAuditDir locks the regression for
// the silent-skip variant: if the audit directory cannot be resolved (e.g.
// neither XDG_STATE_HOME nor HOME is set), WrapCommand must return a non-nil
// error and an empty argv rather than silently omit the tmpfs mask and run
// the child without it.
func TestSandboxNet_FailsClosedOnUnresolvableAuditDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	gotCmd, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err == nil {
		t.Fatalf("expected WrapCommand to fail closed with no XDG_STATE_HOME / HOME, got cmd=%q args=%v", gotCmd, gotArgs)
	}
	if gotCmd != "" || len(gotArgs) != 0 {
		t.Errorf("on failure WrapCommand must return empty cmd/args, got cmd=%q args=%v", gotCmd, gotArgs)
	}
}

// TestSandboxFull_DoesNotInvokeAuditDirResolver — the audit-dir resolution
// branch is intentionally scoped to SandboxNet. SandboxFull tmpfs-masks /home
// wholesale, so it must not gain a transitive failure mode on a missing HOME.
// We blank XDG_STATE_HOME and HOME and assert WrapCommand(SandboxFull, ...)
// still produces a valid argv.
func TestSandboxFull_DoesNotInvokeAuditDirResolver(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	_, gotArgs, err := WrapCommand(SandboxFull, "true", nil)
	if err != nil {
		t.Fatalf("WrapCommand(SandboxFull) must not depend on audit-dir resolution; got err=%v", err)
	}
	// Sanity: SandboxFull still emits its own argv shape, including the
	// --setenv HOME /tmp pair that's irrelevant to the resolver but useful
	// as evidence the SandboxFull branch ran.
	if !hasSeq(gotArgs, []string{"--setenv", "HOME", "/tmp"}) {
		t.Errorf("SandboxFull argv missing '--setenv HOME /tmp': %v", gotArgs)
	}
	if !hasSeq(gotArgs, []string{"--tmpfs", "/home"}) {
		t.Errorf("SandboxFull argv missing '--tmpfs /home': %v", gotArgs)
	}
}

// ----- helpers -----

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func hasSeq(args []string, seq []string) bool {
	if len(seq) == 0 {
		return true
	}
	for i := 0; i+len(seq) <= len(args); i++ {
		ok := true
		for j, s := range seq {
			if args[i+j] != s {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
