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
	for _, want := range []string{"--unshare-net", "--dev-bind", "--die-with-parent", "--new-session"} {
		if !containsArg(gotArgs, want) {
			t.Errorf("net argv missing %q: %v", want, gotArgs)
		}
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
