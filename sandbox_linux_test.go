//go:build linux

package main

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// TestSandboxNet_TmpfsMasksContainerRuntimes (P0-1 / P1-2) — the SandboxNet
// argv must mask container-runtime socket directories (Docker, containerd,
// podman, CRI-O, k3s, LXD, Incus, libvirt, BuildKit, Avahi) and the system
// D-Bus directory with tmpfs so the AI subprocess cannot connect() to those
// AF_UNIX endpoints. --ro-bind / / blocks WRITE but not connect(); without
// these masks an operator-in-docker-group host is trivially exploitable.
//
// Existence-gated: the mask is only emitted for paths that exist on the test
// host. We therefore assert the union — for every entry in runtimeSocketDirs
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

// TestSandboxNet_BindNullMasksContainerSockets (P0-1) — top-level socket
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
// `curl --unix-socket /var/run/docker.sock` — AF_UNIX is FS-namespaced,
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
