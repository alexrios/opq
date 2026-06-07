//go:build linux

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSandboxNet_TmpfsMasksContainerRuntimes (P0-1 / P1-2): the SandboxNet
// argv must mask container-runtime socket directories (Docker, containerd,
// podman, CRI-O, k3s, LXD, Incus, libvirt, BuildKit, Avahi) and the system
// D-Bus directory with tmpfs so the AI subprocess cannot connect() to those
// AF_UNIX endpoints. --ro-bind / / blocks WRITE but not connect(); without
// these masks an operator-in-docker-group host is trivially exploitable.
//
// Existence-gated: the mask is only emitted for paths that exist on the test
// host. We therefore assert the union: for every entry in runtimeSocketDirs
// that exists on the host, the argv MUST contain a --tmpfs <path> pair after
// --ro-bind / /. If NONE exist on the host, the test still verifies the argv
// builder did not regress for the audit-dir / static-tmpfs masks.
func TestSandboxNet_TmpfsMasksContainerRuntimes(t *testing.T) {
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
	roBindIdx := indexOf(gotArgs, "--ro-bind")
	if roBindIdx < 0 {
		t.Fatalf("--ro-bind missing from SandboxNet argv: %v", gotArgs)
	}
	checked := 0
	for _, dir := range runtimeSocketDirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		checked++
		if !hasSeq(gotArgs, []string{"--tmpfs", dir}) {
			t.Errorf("SandboxNet argv missing '--tmpfs %s' (host has the dir; mask required): %v", dir, gotArgs)
			continue
		}
		// Mask must come AFTER --ro-bind / / (left-to-right shadowing).
		for i := 0; i+1 < len(gotArgs); i++ {
			if gotArgs[i] == "--tmpfs" && gotArgs[i+1] == dir {
				if i < roBindIdx {
					t.Errorf("--tmpfs %s (idx %d) must come AFTER --ro-bind (idx %d): %v",
						dir, i, roBindIdx, gotArgs)
				}
				break
			}
		}
	}
	// Vacuity guard (Kimi gate 2 P2): if the host has none of the candidate
	// runtime dirs, the positive loop above passes without ever exercising
	// the mask code. Skip with a loud message in that case so the test
	// report's "skipped" count surfaces the coverage gap. In CI we still
	// fail loudly because at least the developer workstation that runs
	// `go test` while developing this fix MUST have some runtime present
	// for the positive assertions to mean anything. The FakeSocketMask
	// integration test provides technique coverage that does not depend on
	// host state.
	if checked == 0 {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI runner has zero runtime-socket dirs from %v; positive mask coverage would be vacuous", runtimeSocketDirs)
		}
		t.Skipf("no runtime socket dirs from %v present on this host; positive assertions vacuous (negative assertions below still run)", runtimeSocketDirs)
	}
	t.Logf("verified %d/%d candidate runtime-socket dirs masked on this host", checked, len(runtimeSocketDirs))
	// Negative: a candidate that does NOT exist on the host must NOT appear in
	// the argv (existence-gating regression: emitting --tmpfs on a missing
	// target makes bwrap fail "Can't mkdir" and breaks every run_with_secrets
	// call on hosts without that runtime).
	for _, dir := range runtimeSocketDirs {
		if _, err := os.Stat(dir); err == nil {
			continue
		}
		if hasSeq(gotArgs, []string{"--tmpfs", dir}) {
			t.Errorf("SandboxNet argv contains '--tmpfs %s' but the dir does not exist on host (would fail bwrap): %v", dir, gotArgs)
		}
	}
}

// TestSandboxNet_BindNullMasksContainerSockets (P0-1): top-level socket
// FILES (where tmpfs cannot mount, "Not a directory") must be replaced with
// /dev/null via --bind. Like the directory masks, only files present on
// the host are emitted; bwrap's --bind-try does NOT skip on missing
// destinations under --ro-bind / / (verified against bwrap 0.11.0 in
// Kimi gate 1), so the existence check is load-bearing.
func TestSandboxNet_BindNullMasksContainerSockets(t *testing.T) {
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
	roBindIdx := indexOf(gotArgs, "--ro-bind")
	if roBindIdx < 0 {
		t.Fatalf("--ro-bind missing from SandboxNet argv: %v", gotArgs)
	}
	checked := 0
	for _, path := range runtimeSocketFiles {
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		// Mirror appendRuntimeSocketMasks' ModeSocket gate (Kimi gate 2 P1):
		// regular-file entries with the same path shouldn't trigger a mask,
		// so they shouldn't trigger the positive assertion either.
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		checked++
		if !hasSeq(gotArgs, []string{"--bind", "/dev/null", path}) {
			t.Errorf("SandboxNet argv missing '--bind /dev/null %s' (host has the socket; mask required): %v", path, gotArgs)
			continue
		}
		// Mask must come AFTER --ro-bind / /.
		for i := 0; i+2 < len(gotArgs); i++ {
			if gotArgs[i] == "--bind" && gotArgs[i+1] == "/dev/null" && gotArgs[i+2] == path {
				if i < roBindIdx {
					t.Errorf("--bind /dev/null %s (idx %d) must come AFTER --ro-bind (idx %d): %v",
						path, i, roBindIdx, gotArgs)
				}
				break
			}
		}
	}
	// Vacuity guard (Kimi gate 2 P2): see TestSandboxNet_TmpfsMasksContainerRuntimes
	// for the rationale. Most CI runners will have at least /run/docker.sock
	// (rootless Docker installs the socket even when the daemon is stopped),
	// so the CI gate is reasonable. The FakeSocketMaskTechnique integration
	// test covers the bind technique on hosts where none of the canonical
	// sockets are present.
	if checked == 0 {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI runner has zero runtime-socket files from %v; positive mask coverage would be vacuous", runtimeSocketFiles)
		}
		t.Skipf("no runtime socket files from %v present on this host; positive assertions vacuous (negative assertions below still run)", runtimeSocketFiles)
	}
	t.Logf("verified %d/%d candidate runtime-socket files masked on this host", checked, len(runtimeSocketFiles))
	// Negative: missing socket files must NOT appear (would crash bwrap on
	// hosts without that runtime). Also covers the not-a-socket case: an
	// entry whose path exists but is e.g. a regular file must also be
	// skipped by appendRuntimeSocketMasks per the ModeSocket guard there.
	for _, path := range runtimeSocketFiles {
		st, err := os.Stat(path)
		if err == nil && st.Mode()&os.ModeSocket != 0 {
			continue // this one IS a socket; covered by positive loop
		}
		if hasSeq(gotArgs, []string{"--bind", "/dev/null", path}) {
			t.Errorf("SandboxNet argv contains '--bind /dev/null %s' but the file is missing or not a socket on host (would fail bwrap / mask wrong inode): %v", path, gotArgs)
		}
	}
}

// TestSandboxNetAllowed_InheritsRuntimeSocketMasks (P0-1/P1-2 cross-profile)
// locks the joint-review 2026-05 fix for SandboxNetAllowed too.
// SandboxNetAllowed shares sandboxNetArgvCommon with SandboxNet, so the
// container-runtime masks must appear there as well. Without this, an AI
// calling run_with_secrets with allow_network=true could still
// `curl --unix-socket /var/run/docker.sock`; AF_UNIX is FS-namespaced,
// NOT net-namespaced, so omitting --unshare-net does not affect this vector.
func TestSandboxNetAllowed_InheritsRuntimeSocketMasks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("/bin/true not present")
	}
	_, gotArgs, err := WrapCommand(SandboxNetAllowed, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, dir := range runtimeSocketDirs {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			if !hasSeq(gotArgs, []string{"--tmpfs", dir}) {
				t.Errorf("SandboxNetAllowed argv missing '--tmpfs %s' (shared mask drift between profiles): %v", dir, gotArgs)
			}
		}
	}
	for _, path := range runtimeSocketFiles {
		st, err := os.Stat(path)
		if err == nil && st.Mode()&os.ModeSocket != 0 {
			if !hasSeq(gotArgs, []string{"--bind", "/dev/null", path}) {
				t.Errorf("SandboxNetAllowed argv missing '--bind /dev/null %s' (shared mask drift between profiles): %v", path, gotArgs)
			}
		}
	}
}

// withFakeHome points homeDirForMask at a fresh tempdir for the duration of
// the test and restores the original on cleanup. Returning the path is
// convenient for fixture placement; restoring the var via t.Cleanup keeps
// parallel-test isolation if the broader suite gains parallelism later.
func withFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := homeDirForMask
	homeDirForMask = func() (string, error) { return dir, nil }
	t.Cleanup(func() { homeDirForMask = orig })
	return dir
}

// TestSandboxNet_TmpfsMasksHomeDirSockets (gap #3 residual close): the
// home-directory credential-agent socket directories listed in
// homeDirSocketTmpfsRel must be tmpfs-masked when they exist on the
// (fake) host. The mask is what prevents an AI under default SandboxNet
// from connecting to gpg-agent via $HOME/.gnupg/S.gpg-agent and signing
// arbitrary payloads as the operator.
func TestSandboxNet_TmpfsMasksHomeDirSockets(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	home := withFakeHome(t)
	// Create every candidate dir so the positive assertion is non-vacuous.
	for _, rel := range homeDirSocketTmpfsRel {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(full, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
	}
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	roBindIdx := indexOf(gotArgs, "--ro-bind")
	if roBindIdx < 0 {
		t.Fatalf("--ro-bind missing from SandboxNet argv: %v", gotArgs)
	}
	for _, rel := range homeDirSocketTmpfsRel {
		full := filepath.Join(home, rel)
		if !hasSeq(gotArgs, []string{"--tmpfs", full}) {
			t.Errorf("SandboxNet argv missing '--tmpfs %s' (home-dir socket dir mask): %v", full, gotArgs)
			continue
		}
		// Mask must come AFTER --ro-bind / / for left-to-right shadowing.
		for i := 0; i+1 < len(gotArgs); i++ {
			if gotArgs[i] == "--tmpfs" && gotArgs[i+1] == full {
				if i < roBindIdx {
					t.Errorf("--tmpfs %s (idx %d) must come AFTER --ro-bind (idx %d): %v",
						full, i, roBindIdx, gotArgs)
				}
				break
			}
		}
	}
}

// TestSandboxNet_HomeDirMasksAbsentWhenDirMissing: when the candidate
// home-dir socket dir does NOT exist on the host, no --tmpfs entry for
// it may appear in the argv. Without existence-gating, bwrap fails with
// "Can't mkdir <path>" on every run_with_secrets call on hosts where
// the operator does not have e.g. ~/.gnupg.
func TestSandboxNet_HomeDirMasksAbsentWhenDirMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	home := withFakeHome(t)
	// Do NOT create any of the candidate dirs / files under home.
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, rel := range homeDirSocketTmpfsRel {
		full := filepath.Join(home, rel)
		if hasSeq(gotArgs, []string{"--tmpfs", full}) {
			t.Errorf("SandboxNet argv contains '--tmpfs %s' but the dir does not exist (would fail bwrap): %v", full, gotArgs)
		}
	}
	for _, rel := range homeDirSocketFileRel {
		full := filepath.Join(home, rel)
		if hasSeq(gotArgs, []string{"--bind", "/dev/null", full}) {
			t.Errorf("SandboxNet argv contains '--bind /dev/null %s' but the file does not exist (would fail bwrap): %v", full, gotArgs)
		}
	}
}

// TestSandboxNet_BindNullMasksHomeDirSocketFiles: for each entry in
// homeDirSocketFileRel that exists on the (fake) host AND is a socket,
// the argv must contain '--bind /dev/null <path>'. The bind replaces
// the socket with /dev/null which refuses connect(2). We create a real
// AF_UNIX socket under the fake home so the ModeSocket gate in
// appendHomeDirSocketMasks fires positively.
func TestSandboxNet_BindNullMasksHomeDirSocketFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	home := withFakeHome(t)
	created := 0
	for _, rel := range homeDirSocketFileRel {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("mkdir parent of %s: %v", full, err)
		}
		// Create a real AF_UNIX listener so os.Stat sees ModeSocket.
		// Closing the listener keeps the socket file on disk (closeRemove
		// is not the default); we Close explicitly and let the file
		// linger until t.TempDir cleanup.
		l, err := net.Listen("unix", full)
		if err != nil {
			// Path length limits on some kernels (108 chars) may reject
			// the fake-home path; skip the per-entry assertion and
			// continue rather than failing.
			t.Logf("could not create socket at %s: %v (skipping this entry)", full, err)
			continue
		}
		_ = l.Close()
		created++
	}
	if created == 0 {
		t.Skip("could not create any home-dir socket fixtures (kernel sun_path limit?)")
	}
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	roBindIdx := indexOf(gotArgs, "--ro-bind")
	if roBindIdx < 0 {
		t.Fatalf("--ro-bind missing from SandboxNet argv: %v", gotArgs)
	}
	for _, rel := range homeDirSocketFileRel {
		full := filepath.Join(home, rel)
		st, err := os.Stat(full)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			continue
		}
		if !hasSeq(gotArgs, []string{"--bind", "/dev/null", full}) {
			t.Errorf("SandboxNet argv missing '--bind /dev/null %s' (home-dir socket file mask): %v", full, gotArgs)
			continue
		}
		for i := 0; i+2 < len(gotArgs); i++ {
			if gotArgs[i] == "--bind" && gotArgs[i+1] == "/dev/null" && gotArgs[i+2] == full {
				if i < roBindIdx {
					t.Errorf("--bind /dev/null %s (idx %d) must come AFTER --ro-bind (idx %d): %v",
						full, i, roBindIdx, gotArgs)
				}
				break
			}
		}
	}
}

// TestSandboxNet_HomeDirRegularFileNotMasked: regression for the
// ModeSocket gate: if the path exists but is a regular file (not a
// socket), it must NOT be masked. Without this gate, an unusual host
// state (file with the same name as the expected socket) would crash
// bwrap with a Read-only filesystem error under --ro-bind / /.
func TestSandboxNet_HomeDirRegularFileNotMasked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	home := withFakeHome(t)
	for _, rel := range homeDirSocketFileRel {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("mkdir parent of %s: %v", full, err)
		}
		// Write a regular file (NOT a socket) at the path.
		if err := os.WriteFile(full, []byte("not a socket"), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, rel := range homeDirSocketFileRel {
		full := filepath.Join(home, rel)
		if hasSeq(gotArgs, []string{"--bind", "/dev/null", full}) {
			t.Errorf("SandboxNet argv masked %s but it is a regular file, not a socket: %v", full, gotArgs)
		}
	}
}

// TestSandboxNet_HomeDirMaskHomeUnsetFallsOpen: when the operator's
// $HOME cannot be resolved (no $HOME set, /etc/passwd missing), the
// home-dir masks are skipped silently (fail-open) rather than refusing
// the whole sandbox. The broader masks (/run/user, /run/dbus, etc.)
// still apply; the residual is that custom home-dir sockets remain
// reachable; same posture opq has always had on hosts where $HOME
// is unset. CLI calls would fail elsewhere (HOME=/tmp injected for
// the child) so this case is only reachable in adversarial test envs,
// but the fail-open behavior is the right invariant.
func TestSandboxNet_HomeDirMaskHomeUnsetFallsOpen(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only sandbox")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not present")
	}
	orig := homeDirForMask
	homeDirForMask = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { homeDirForMask = orig })
	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("err = %v (home-unset must fall open, not error)", err)
	}
	// Sanity: the rest of the argv (--ro-bind, --tmpfs /run/user) is
	// still present so we didn't accidentally skip the whole common slice.
	if !hasSeq(gotArgs, []string{"--ro-bind", "/", "/"}) {
		t.Errorf("home-unset path dropped --ro-bind / /: %v", gotArgs)
	}
	if !hasSeq(gotArgs, []string{"--tmpfs", "/run/user"}) {
		t.Errorf("home-unset path dropped --tmpfs /run/user: %v", gotArgs)
	}
}
