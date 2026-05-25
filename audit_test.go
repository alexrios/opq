package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func withAuditTmpDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)
	// Reset shared state between tests.
	auditMu.Lock()
	if auditFile != nil {
		auditFile.Close()
		auditFile = nil
	}
	auditWarnOnce = sync.Once{}
	auditMu.Unlock()
	return tmp
}

func TestAppendAudit_FileModeAndAppend(t *testing.T) {
	tmp := withAuditTmpDir(t)

	if err := AppendAudit(AuditEvent{Action: ActionList}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := AppendAudit(AuditEvent{Action: ActionGet, SecretName: "openai_api_key"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	path := filepath.Join(tmp, "opq", "audit.log")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), data)
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Action != ActionGet || ev.SecretName != "openai_api_key" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.PID == 0 || ev.Timestamp.IsZero() {
		t.Errorf("PID/Timestamp not populated: %+v", ev)
	}
}

func TestTailAudit(t *testing.T) {
	withAuditTmpDir(t)
	for i := 0; i < 5; i++ {
		if err := AppendAudit(AuditEvent{Action: ActionList, Message: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	lines, err := tailAudit(2)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[1], `"msg":"e"`) {
		t.Errorf("expected last line to have msg=e, got %s", lines[1])
	}
}

func TestTailAudit_MissingFile(t *testing.T) {
	withAuditTmpDir(t)
	lines, err := tailAudit(10)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected empty, got %v", lines)
	}
}

// TestOpenAudit_RefusesSymlinkFile verifies that O_NOFOLLOW causes the audit
// open to refuse if audit.log itself is a symlink (symlink-swap attack).
func TestOpenAudit_RefusesSymlinkFile(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Plant a symlink where audit.log would be created.
	target := filepath.Join(tmp, "evil-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, logPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := AppendAudit(AuditEvent{Action: ActionList})
	if err == nil {
		t.Fatal("expected AppendAudit to refuse symlinked audit.log, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink-refusal error, got: %v", err)
	}
	// Verify the symlink target was not written through.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if len(data) != 0 {
		t.Errorf("symlink target was written through despite O_NOFOLLOW: %q", data)
	}
}

// TestOpenAudit_RefusesSymlinkDir verifies prepareAuditDir refuses when the
// $XDG_STATE_HOME/opq directory itself is a symlink.
func TestOpenAudit_RefusesSymlinkDir(t *testing.T) {
	tmp := withAuditTmpDir(t)
	realDir := filepath.Join(tmp, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	// Symlink $XDG_STATE_HOME/opq -> real
	if err := os.Symlink(realDir, filepath.Join(tmp, "opq")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := AppendAudit(AuditEvent{Action: ActionList})
	if err == nil {
		t.Fatal("expected AppendAudit to refuse symlinked audit dir, got nil")
	}
	// With O_NOFOLLOW|O_DIRECTORY, opening a symlink-to-directory returns
	// ENOTDIR on Linux rather than ELOOP, so the refusal message can mention
	// "symlink" (raw ELOOP path) or "not a directory" (ENOTDIR path). Either
	// is a correct refusal of the symlink-swap attack.
	msg := err.Error()
	if !strings.Contains(msg, "symlink") && !strings.Contains(msg, "not a directory") {
		t.Errorf("expected symlink-refusal error, got: %v", err)
	}
}

// TestPrepareAuditDir_TightensWideMode verifies that an existing audit dir
// with loose perms (e.g. 0o755) is tightened to 0o700.
func TestPrepareAuditDir_TightensWideMode(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Force perms in case umask narrowed them.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := AppendAudit(AuditEvent{Action: ActionList}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("audit dir mode = %o, want 0700", info.Mode().Perm())
	}
}

// TestRotation_AtThreshold verifies that when the active log exceeds the
// rotation threshold, the next write triggers a rename to .log.1 and a fresh
// .log file is opened. Also verifies that a pre-existing .log.1 is overwritten.
func TestRotation_AtThreshold(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	rotPath := logPath + ".1"

	// Plant an old .log.1 we expect to be overwritten by rotation.
	if err := os.WriteFile(rotPath, []byte("OLD_ROTATION\n"), 0o600); err != nil {
		t.Fatalf("seed rotpath: %v", err)
	}
	// Plant a current audit.log that is already over the threshold.
	big := bytes.Repeat([]byte("x"), auditRotateThreshold+1)
	if err := os.WriteFile(logPath, big, 0o600); err != nil {
		t.Fatalf("seed logpath: %v", err)
	}

	if err := AppendAudit(AuditEvent{Action: ActionList, Message: "post-rotate"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	// audit.log.1 should now contain the pre-rotation content (~ size big).
	rotInfo, err := os.Stat(rotPath)
	if err != nil {
		t.Fatalf("stat .1: %v", err)
	}
	if rotInfo.Size() < int64(auditRotateThreshold) {
		t.Errorf(".log.1 size = %d, want >= %d (should contain pre-rotation content)", rotInfo.Size(), auditRotateThreshold)
	}
	// audit.log should be fresh and small, containing just the new event.
	curInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if curInfo.Size() >= int64(auditRotateThreshold) {
		t.Errorf("post-rotation audit.log size = %d, expected small", curInfo.Size())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "post-rotate") {
		t.Errorf("post-rotation audit.log does not contain new event: %q", data)
	}
	// Verify only .log and .log.1 exist (no .log.2 etc).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != "audit.log" && name != "audit.log.1" {
			t.Errorf("unexpected file in audit dir: %s", name)
		}
	}
}

// TestAppendAudit_WarnOnceOnFailure verifies that the first audit error emits
// a single stderr warning, and that subsequent errors do not re-emit.
func TestAppendAudit_WarnOnceOnFailure(t *testing.T) {
	withAuditTmpDir(t)
	// Force failures by pointing XDG_STATE_HOME at a non-writable path.
	// We use a path under /proc (read-only) as a portable way to make
	// MkdirAll/OpenFile fail on Linux.
	t.Setenv("XDG_STATE_HOME", "/proc/1/audit-cannot-write")

	// Capture stderr.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	err1 := AppendAudit(AuditEvent{Action: ActionList, Message: "first"})
	if err1 == nil {
		t.Fatal("expected first AppendAudit to fail")
	}
	err2 := AppendAudit(AuditEvent{Action: ActionList, Message: "second"})
	if err2 == nil {
		t.Fatal("expected second AppendAudit to fail")
	}

	w.Close()
	os.Stderr = origStderr
	captured, _ := io.ReadAll(r)
	out := string(captured)

	if !strings.Contains(out, "AUDIT LOG WRITE FAILED") {
		t.Errorf("expected loud stderr warning on first failure, got: %q", out)
	}
	if strings.Count(out, "AUDIT LOG WRITE FAILED") != 1 {
		t.Errorf("warning should be emitted exactly once, got: %q", out)
	}
	// Both errors should still be returned to the caller (API unchanged).
	if !errors.Is(err1, err1) || err2 == nil {
		t.Errorf("both calls should still return errors; got %v, %v", err1, err2)
	}
}

// TestTailAudit_RefusesSymlink verifies tailAudit refuses to follow a symlink
// at the audit.log path.
func TestTailAudit_RefusesSymlink(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(tmp, "real-audit.log")
	if err := os.WriteFile(target, []byte(`{"action":"hijack"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "audit.log")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := tailAudit(10)
	if err == nil {
		t.Fatal("expected tailAudit to refuse symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink-refusal, got: %v", err)
	}
}

// Sanity check: confirm syscall.ELOOP is wired so detection works at runtime.
func TestSyscall_ELOOPDefined(t *testing.T) {
	if syscall.ELOOP == 0 {
		t.Fatal("syscall.ELOOP not defined")
	}
}
