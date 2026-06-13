//go:build darwin

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// seatbeltProfile extracts the SBPL profile string and the resolved command
// token from a WrapCommand result. The argv shape is:
//
//	sandbox-exec -p <profile> <abs-cmd> <args...>
func seatbeltProfile(t *testing.T, args []string) (profile, cmd string) {
	t.Helper()
	i := indexOf(args, "-p")
	if i < 0 {
		t.Fatalf("argv missing -p flag: %v", args)
	}
	if i+2 >= len(args) {
		t.Fatalf("argv truncated after -p: %v", args)
	}
	return args[i+1], args[i+2]
}

func TestWrapCommand_SandboxNet_Seatbelt(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not present")
	}
	gotCmd, gotArgs, err := WrapCommand(SandboxNet, "true", []string{"arg1"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if filepath.Base(gotCmd) != "sandbox-exec" {
		t.Errorf("wrapper cmd = %q, want sandbox-exec", gotCmd)
	}
	profile, resolved := seatbeltProfile(t, gotArgs)
	if !filepath.IsAbs(resolved) {
		t.Errorf("command token must be absolute, got %q", resolved)
	}
	// arg1 must follow the command token, untouched.
	if gotArgs[len(gotArgs)-1] != "arg1" {
		t.Errorf("trailing arg not preserved: %v", gotArgs)
	}
	for _, want := range []string{"(version 1)", "(deny network*)", "(deny file-write*)"} {
		if !strings.Contains(profile, want) {
			t.Errorf("SandboxNet profile missing %q:\n%s", want, profile)
		}
	}
}

func TestWrapCommand_SandboxNetAllowed_Seatbelt(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not present")
	}
	gotCmd, gotArgs, err := WrapCommand(SandboxNetAllowed, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if filepath.Base(gotCmd) != "sandbox-exec" {
		t.Errorf("wrapper cmd = %q, want sandbox-exec (allow_network must NOT bypass the sandbox)", gotCmd)
	}
	profile, _ := seatbeltProfile(t, gotArgs)
	// FS sandbox must be present...
	if !strings.Contains(profile, "(deny file-write*)") {
		t.Errorf("net-allowed profile missing FS sandbox '(deny file-write*)':\n%s", profile)
	}
	// ...but the network deny must be ABSENT; that is the defining difference.
	if strings.Contains(profile, "(deny network*)") {
		t.Errorf("net-allowed profile MUST NOT deny network:\n%s", profile)
	}
}

func TestWrapCommand_SandboxFull_Seatbelt(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not present")
	}
	_, gotArgs, err := WrapCommand(SandboxFull, "true", nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	profile, _ := seatbeltProfile(t, gotArgs)
	for _, want := range []string{
		"(deny network*)",
		"(deny file-write*)",
		`(deny file-read* (subpath "/Users"))`,
		`(deny file-read* (subpath "/private/tmp"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("SandboxFull profile missing %q:\n%s", want, profile)
		}
	}
}

// TestSandboxNet_MasksAuditDir locks the J-12 analogue: SandboxNet must deny
// reads of the resolved audit directory so the child can't cat audit.log and
// recover filtered tokens.
func TestSandboxNet_MasksAuditDir(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not present")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)

	_, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	profile, _ := seatbeltProfile(t, gotArgs)

	wantDir := filepath.Join(tmp, "opq")
	if resolved, err := filepath.EvalSymlinks(wantDir); err == nil {
		wantDir = resolved
	}
	want := `(deny file-read* (subpath "` + wantDir + `"))`
	if !strings.Contains(profile, want) {
		t.Errorf("SandboxNet profile missing audit-dir mask %q:\n%s", want, profile)
	}
}

// TestSandboxNet_FailsClosedOnUnresolvableAuditDir mirrors the Linux contract:
// if the audit dir can't be resolved (no XDG_STATE_HOME and no HOME),
// WrapCommand must fail closed with an empty argv rather than silently omit the
// mask.
func TestSandboxNet_FailsClosedOnUnresolvableAuditDir_Darwin(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	gotCmd, gotArgs, err := WrapCommand(SandboxNet, "true", nil)
	if err == nil {
		t.Fatalf("expected fail-closed with no XDG_STATE_HOME / HOME, got cmd=%q args=%v", gotCmd, gotArgs)
	}
	if gotCmd != "" || len(gotArgs) != 0 {
		t.Errorf("on failure WrapCommand must return empty cmd/args, got cmd=%q args=%v", gotCmd, gotArgs)
	}
}

// TestSandboxFull_DoesNotDependOnAuditOrHome: SandboxFull must not gain a
// failure mode on a missing HOME (it denies /Users wholesale instead of
// resolving $HOME), matching the Linux backend's contract.
func TestSandboxFull_DoesNotDependOnAuditOrHome(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not present")
	}
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	_, gotArgs, err := WrapCommand(SandboxFull, "true", nil)
	if err != nil {
		t.Fatalf("SandboxFull must not depend on audit/home resolution; got err=%v", err)
	}
	profile, _ := seatbeltProfile(t, gotArgs)
	if !strings.Contains(profile, `(deny file-read* (subpath "/Users"))`) {
		t.Errorf("SandboxFull profile missing /Users mask:\n%s", profile)
	}
}

func TestVerifySandboxAvailable_Darwin_OK(t *testing.T) {
	resetSandboxVerifyCacheForTest()
	t.Cleanup(resetSandboxVerifyCacheForTest)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatalf("VerifySandboxAvailable: %v", err)
	}
}

func TestVerifySandboxAvailable_Darwin_Missing(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	resetSandboxVerifyCacheForTest()
	t.Cleanup(resetSandboxVerifyCacheForTest)

	err := VerifySandboxAvailable()
	if err == nil {
		t.Fatalf("expected error when sandbox-exec is unreachable")
	}
	if !strings.Contains(err.Error(), "sandbox-exec") {
		t.Errorf("error should name sandbox-exec, got: %v", err)
	}
}

// TestVerifySandboxAvailable_Darwin_Caches locks the sync.Once cache: after a
// success, a sabotaged PATH must still return the cached nil.
func TestVerifySandboxAvailable_Darwin_Caches(t *testing.T) {
	resetSandboxVerifyCacheForTest()
	t.Cleanup(resetSandboxVerifyCacheForTest)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatalf("first call: %v", err)
	}
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatalf("second call should be cached success, got: %v", err)
	}
}

// TestSandboxNet_ProfileParsesUnderSandboxExec is a functional smoke test: the
// generated SandboxNet profile must be accepted by the real sandbox-exec (a
// malformed SBPL string would be rejected at apply time). We run /usr/bin/true
// under it and require a clean exit.
func TestSandboxNet_ProfileParsesUnderSandboxExec(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	wrapCmd, wrapArgs, err := WrapCommand(SandboxNet, "/usr/bin/true", nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	out, err := exec.Command(wrapCmd, wrapArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-exec rejected generated SandboxNet profile: %v\noutput: %s", err, strings.TrimSpace(string(out)))
	}
}

func TestSandboxFull_ProfileParsesUnderSandboxExec(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	wrapCmd, wrapArgs, err := WrapCommand(SandboxFull, "/usr/bin/true", nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	out, err := exec.Command(wrapCmd, wrapArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-exec rejected generated SandboxFull profile: %v\noutput: %s", err, strings.TrimSpace(string(out)))
	}
}
