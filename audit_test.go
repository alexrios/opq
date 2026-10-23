package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestMain dispatches early on OPQ_TEST_AUDIT_HAMMER so the same test
// binary can be re-exec'd as an audit-write hammer subprocess. See
// TestAppendAudit_MultiprocessFlock for the consumer.
//
// A second mode, OPQ_TEST_TAIL_HAMMER_WRITER, runs a tighter loop that
// writes large padded events for a bounded duration so a parent reader
// process can race against rotation. The threshold is overridden through
// OPQ_TEST_ROTATE_BYTES because subprocesses do not share package state.
func TestMain(m *testing.M) {
	if os.Getenv("OPQ_TEST_AUDIT_ROTATE_ONCE") == "1" {
		auditRotateThreshold = 1
		if err := AppendAudit(AuditEvent{Action: "test_rotation", Message: "other_process"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("OPQ_TEST_AUDIT_HAMMER") == "1" {
		for i := 0; i < 200; i++ {
			_ = AppendAudit(AuditEvent{Action: "test_hammer", Message: fmt.Sprintf("hammer-%d", i)})
		}
		os.Exit(0)
	}
	if os.Getenv("OPQ_TEST_TAIL_HAMMER_WRITER") == "1" {
		if v := os.Getenv("OPQ_TEST_ROTATE_BYTES"); v != "" {
			var n int64
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
				auditRotateThreshold = n
			}
		}
		durMs := 500
		if v := os.Getenv("OPQ_TEST_TAIL_HAMMER_MS"); v != "" {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
				durMs = n
			}
		}
		deadline := time.Now().Add(time.Duration(durMs) * time.Millisecond)
		pad := strings.Repeat("p", 256)
		pid := os.Getpid()
		for seq := 0; seq < 32 || time.Now().Before(deadline); seq++ {
			_ = AppendAudit(AuditEvent{
				Action:  "tail_hammer",
				Message: fmt.Sprintf("p%d-seq-%d-%s", pid, seq, pad),
			})
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func withAuditTmpDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)
	setPolicyHomeForTest(t, tmp)
	// Reset shared state between tests. The lock file is process-global
	// in production but per-test here so different temp dirs don't share
	// a stale fd pointing into an already-cleaned-up directory.
	auditMu.Lock()
	if auditFile != nil {
		auditFile.Close()
		auditFile = nil
	}
	if auditLockFile != nil {
		auditLockFile.Close()
		auditLockFile = nil
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

// TestAuditEvent_NonceFieldRoundTrip locks the JSON shape of the new
// Nonce field (joint-review 2026-05 P3-1). Empty Nonce must be omitted
// from the serialized form so existing tools that grep the log for
// known keys do not see an unfamiliar `nonce:""`. A populated Nonce
// must round-trip cleanly through Marshal/Unmarshal so the strip in
// handleAuditTail can match it byte-for-byte after the line passes
// through filterAuditLineForAI's re-marshal.
func TestAuditEvent_NonceFieldRoundTrip(t *testing.T) {
	t.Run("empty omitted", func(t *testing.T) {
		ev := AuditEvent{Action: ActionAuditTail, Caller: "mcp", Message: "n=20"}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(raw, []byte("nonce")) {
			t.Errorf("empty Nonce leaked into JSON: %s", raw)
		}
	})
	t.Run("populated round-trips", func(t *testing.T) {
		original := AuditEvent{
			Action: ActionAuditTail,
			Caller: "mcp",
			Nonce:  "0123456789abcdef0123456789abcdef",
		}
		raw, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Contains(raw, []byte(`"nonce":"0123456789abcdef0123456789abcdef"`)) {
			t.Errorf("nonce missing from JSON: %s", raw)
		}
		var got AuditEvent
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Nonce != original.Nonce {
			t.Errorf("nonce mismatch: got %q, want %q", got.Nonce, original.Nonce)
		}
	})
	t.Run("legacy entries parse", func(t *testing.T) {
		// A log line written by an older opq version (no nonce field at
		// all) must unmarshal cleanly with empty Nonce; the strip
		// scanner relies on this to skip such entries without crashing.
		const legacy = `{"ts":"2026-05-01T00:00:00Z","action":"audit_tail","caller":"mcp","pid":42,"ppid":1,"msg":"n=20"}`
		var ev AuditEvent
		if err := json.Unmarshal([]byte(legacy), &ev); err != nil {
			t.Fatalf("unmarshal legacy: %v", err)
		}
		if ev.Nonce != "" {
			t.Errorf("expected empty nonce from legacy entry, got %q", ev.Nonce)
		}
	})
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
	big := bytes.Repeat([]byte("x"), int(auditRotateThreshold)+1)
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
	// Verify only .log, .log.1, and the rotation-immune .lock exist
	// (no .log.2 etc).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name != "audit.log" && name != "audit.log.1" && name != "audit.lock" {
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

func TestSanitizeBackendErr(t *testing.T) {
	t.Run("not_found_sentinel", func(t *testing.T) {
		if got := sanitizeBackendErr(ErrSecretNotFound); got != "not_found" {
			t.Fatalf("got %q, want %q", got, "not_found")
		}
	})
	t.Run("generic_error_collapses", func(t *testing.T) {
		if got := sanitizeBackendErr(errors.New("any other error")); got != "backend_error" {
			t.Fatalf("got %q, want %q", got, "backend_error")
		}
	})
	t.Run("wrapped_not_found", func(t *testing.T) {
		if got := sanitizeBackendErr(fmt.Errorf("wrap: %w", ErrSecretNotFound)); got != "not_found" {
			t.Fatalf("wrapped ErrSecretNotFound: got %q, want %q", got, "not_found")
		}
	})
	t.Run("hostile_error_text_does_not_leak", func(t *testing.T) {
		// Defense: a backend that embeds secret bytes in its error
		// string must NOT see those bytes routed verbatim to the audit
		// log (which is AI-readable via audit_tail).
		got := sanitizeBackendErr(errors.New("plaintext: sk-abc123"))
		if got != "backend_error" {
			t.Fatalf("got %q, want %q", got, "backend_error")
		}
		if strings.Contains(got, "sk-") {
			t.Fatalf("sanitized output leaked secret-looking prefix: %q", got)
		}
	})
}

func TestAuditEvent_SecretNamesField(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		raw, err := json.Marshal(AuditEvent{Action: ActionMCPRun, SecretNames: []string{"a", "b"}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(raw), `"secret_names":["a","b"]`) {
			t.Fatalf("expected secret_names array, got %s", raw)
		}
	})
	t.Run("omitted_when_empty", func(t *testing.T) {
		raw, err := json.Marshal(AuditEvent{Action: ActionMCPRun})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(raw), "secret_names") {
			t.Fatalf("expected secret_names omitted under omitempty, got %s", raw)
		}
	})
}

func TestTailAudit_ReadsAcrossRotation(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	rotPath := logPath + ".1"

	rot := []string{
		`{"action":"r1"}`,
		`{"action":"r2"}`,
		`{"action":"r3"}`,
		`{"action":"r4"}`,
		`{"action":"r5"}`,
	}
	cur := []string{
		`{"action":"c1"}`,
		`{"action":"c2"}`,
		`{"action":"c3"}`,
	}
	if err := os.WriteFile(rotPath, []byte(strings.Join(rot, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write rot: %v", err)
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(cur, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write cur: %v", err)
	}

	t.Run("spans_rotation", func(t *testing.T) {
		lines, err := tailAudit(6)
		if err != nil {
			t.Fatalf("tailAudit: %v", err)
		}
		want := append([]string{rot[2], rot[3], rot[4]}, cur...)
		if len(lines) != len(want) {
			t.Fatalf("len=%d want %d (%v)", len(lines), len(want), lines)
		}
		for i := range want {
			if lines[i] != want[i] {
				t.Errorf("line[%d] = %q, want %q", i, lines[i], want[i])
			}
		}
	})

	t.Run("active_only_when_sufficient", func(t *testing.T) {
		// Active log has 3 entries; ask for 2, answer must come
		// entirely from active and never need to touch .log.1.
		lines, err := tailAudit(2)
		if err != nil {
			t.Fatalf("tailAudit: %v", err)
		}
		want := []string{cur[1], cur[2]}
		if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
			t.Fatalf("got %v, want %v", lines, want)
		}
	})

	t.Run("zero_returns_all", func(t *testing.T) {
		lines, err := tailAudit(0)
		if err != nil {
			t.Fatalf("tailAudit: %v", err)
		}
		if len(lines) != 8 {
			t.Fatalf("len=%d want 8 (%v)", len(lines), lines)
		}
	})
}

func TestTailAudit_RefusesSymlinkedRotation(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	rotPath := logPath + ".1"

	// Active log has fewer entries than requested, forcing tailAudit
	// to descend into .log.1, which is a symlink we must refuse.
	if err := os.WriteFile(logPath, []byte(`{"action":"a"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	target := filepath.Join(tmp, "other-rotation-target")
	if err := os.WriteFile(target, []byte(`{"action":"hijack"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, rotPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := tailAudit(100)
	if err == nil {
		t.Fatal("expected tailAudit to refuse symlinked .log.1")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink-refusal, got %v", err)
	}
}

// filterEnvOut removes any KEY=... entries whose KEY matches one of keys.
// Needed when re-exec'ing a test subprocess: appending an override to
// os.Environ() does NOT supersede an earlier occurrence; libc's
// getenv returns the first match, so the test's intended value is
// silently ignored if the parent already has the var set.
func filterEnvOut(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	skip := make(map[string]bool, len(keys))
	for _, k := range keys {
		skip[k] = true
	}
	for _, e := range env {
		eq := strings.IndexByte(e, '=')
		if eq <= 0 || !skip[e[:eq]] {
			out = append(out, e)
		}
	}
	return out
}

// TestAppendAudit_MultiprocessFlock spawns two test binaries that each
// hammer the audit log with 200 writes and verifies no lines are lost
// or duplicated across processes. Proves that the lock-file-based
// cross-process serialization survives audit.log rotation.
func TestAppendAudit_MultiprocessFlock(t *testing.T) {
	tmp := t.TempDir()
	bin := os.Args[0]
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("cannot stat test binary %q: %v", bin, err)
	}

	run := func() *exec.Cmd {
		c := exec.Command(bin)
		c.Env = append(
			filterEnvOut(os.Environ(), "XDG_STATE_HOME", "OPQ_TEST_AUDIT_HAMMER"),
			"OPQ_TEST_AUDIT_HAMMER=1",
			"XDG_STATE_HOME="+tmp,
		)
		return c
	}
	c1, c2 := run(), run()
	if err := c1.Start(); err != nil {
		t.Fatalf("start c1: %v", err)
	}
	if err := c2.Start(); err != nil {
		t.Fatalf("start c2: %v", err)
	}
	err1 := c1.Wait()
	err2 := c2.Wait()
	if err1 != nil {
		t.Fatalf("c1 wait: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("c2 wait: %v", err2)
	}

	readLines := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			t.Fatalf("read %s: %v", path, err)
		}
		s := strings.TrimRight(string(data), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	logPath := filepath.Join(tmp, "opq", "audit.log")
	all := append(readLines(logPath+".1"), readLines(logPath)...)
	if len(all) != 400 {
		t.Fatalf("total audit lines = %d, want 400 (no losses)", len(all))
	}
	// Regression guard: duplicate lines would imply either a torn
	// write applied twice or a tailAudit-style open->rotate race
	// reading the same physical inode through both .log and .log.1.
	// Each hammer iteration includes (pid, i) uniqueness, so any
	// duplicate JSON line indicates a real defect.
	seen := make(map[string]int, len(all))
	for _, l := range all {
		seen[l]++
	}
	for line, count := range seen {
		if count > 1 {
			t.Fatalf("duplicate audit line (count=%d): %s", count, line)
		}
	}
}

// TestEnsureAuditLockFile_RefusesSymlink verifies that O_NOFOLLOW causes
// the lock-file open to refuse if audit.lock has been replaced by a
// symlink (lock-file symlink-swap attack).
func TestEnsureAuditLockFile_RefusesSymlink(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(tmp, "evil")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	lockPath := filepath.Join(dir, "audit.lock")
	if err := os.Symlink(target, lockPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := AppendAudit(AuditEvent{Action: ActionList})
	if err == nil {
		t.Fatal("expected AppendAudit to refuse symlinked audit.lock, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink-refusal error, got: %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if len(data) != 0 {
		t.Errorf("symlink target was written through despite O_NOFOLLOW: %q", data)
	}
}

// setAuditRotateThresholdForTest lowers the rotation threshold for the
// duration of a test and restores it on cleanup. Deliberately not exposed
// in production code; auditRotateThreshold is a var purely to enable this.
func setAuditRotateThresholdForTest(t *testing.T, n int64) {
	t.Helper()
	prev := auditRotateThreshold
	auditRotateThreshold = n
	t.Cleanup(func() { auditRotateThreshold = prev })
}

// TestTailAudit_NoDuplicatesUnderConcurrentRotation proves that tailAudit
// holds LOCK_SH across BOTH the active and rotated reads, so a concurrent
// writer's rotation cannot interleave to make the same physical inode
// appear in both halves of the result. Writer goroutine appends large
// events that force frequent rotations against a deliberately tiny
// threshold; reader goroutine tails in a tight loop and asserts no
// returned slice contains duplicate JSON lines.
func TestTailAudit_NoDuplicatesUnderConcurrentRotation(t *testing.T) {
	withAuditTmpDir(t)
	setAuditRotateThresholdForTest(t, 4096)

	stop := make(chan struct{})
	writerProgress := make(chan struct{})
	readerProgress := make(chan struct{})
	var writerErr error
	var wg sync.WaitGroup

	// Writer: each event carries a unique seq so duplicates are visible.
	wg.Add(1)
	go func() {
		defer wg.Done()
		pad := strings.Repeat("p", 256)
		for seq := 0; ; seq++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := AppendAudit(AuditEvent{
				Action:  ActionList,
				Message: fmt.Sprintf("seq-%d-%s", seq, pad),
			}); err != nil {
				writerErr = err
				if seq < 32 {
					close(writerProgress)
				}
				return
			}
			if seq == 31 {
				close(writerProgress)
			}
		}
	}()

	// Reader: tail enough entries to plausibly span a rotation boundary.
	var (
		readerErr      error
		readerErrMu    sync.Mutex
		iterations     int
		duplicateLines []string
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			lines, err := tailAudit(200)
			if err != nil {
				readerErrMu.Lock()
				if readerErr == nil {
					readerErr = err
				}
				readerErrMu.Unlock()
				return
			}
			iterations++
			if iterations == 10 {
				close(readerProgress)
			}
			seen := make(map[string]int, len(lines))
			for _, l := range lines {
				seen[l]++
				if seen[l] > 1 {
					readerErrMu.Lock()
					duplicateLines = append(duplicateLines, l)
					readerErrMu.Unlock()
				}
			}
		}
	}()

	// Require enough writes to rotate and actual reader progress. A fixed
	// sleep can expire before any rotation on a busy build or CI host.
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	timedOut := false
	for _, progress := range []<-chan struct{}{writerProgress, readerProgress} {
		select {
		case <-progress:
		case <-timer.C:
			timedOut = true
		}
		if timedOut {
			break
		}
	}
	close(stop)
	wg.Wait()
	if writerErr != nil {
		t.Fatalf("writer error: %v", writerErr)
	}
	if timedOut {
		t.Fatal("writer or reader failed to make progress within 5 seconds")
	}

	if readerErr != nil {
		t.Fatalf("reader error: %v", readerErr)
	}
	if iterations == 0 {
		t.Fatal("reader made zero iterations; test did not exercise tailAudit")
	}
	if len(duplicateLines) > 0 {
		t.Fatalf("tailAudit returned duplicate lines under concurrent rotation: %d duplicates, sample: %q",
			len(duplicateLines), duplicateLines[0])
	}

	// Sanity: confirm rotation actually fired at least once, otherwise
	// this test is not exercising the race window it claims to.
	dir := filepath.Join(os.Getenv("XDG_STATE_HOME"), "opq")
	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); err != nil {
		t.Fatalf("expected audit.log.1 to exist (proving rotation occurred); stat: %v", err)
	}
}

// TestTailAudit_NoDuplicatesAcrossSequentialRotation is a deterministic
// companion to the concurrent test above: write some lines, rotate
// manually, write more lines, then tail and assert no duplicates and the
// expected count.
func TestTailAudit_NoDuplicatesAcrossSequentialRotation(t *testing.T) {
	tmp := withAuditTmpDir(t)
	for i := 0; i < 3; i++ {
		if err := AppendAudit(AuditEvent{Action: ActionList, Message: fmt.Sprintf("pre-%d", i)}); err != nil {
			t.Fatalf("AppendAudit pre: %v", err)
		}
	}
	dir := filepath.Join(tmp, "opq")
	logPath := filepath.Join(dir, "audit.log")
	rotPath := logPath + ".1"

	// Manually rotate. Need to close the cached fd first or the next
	// write will reopen the (renamed) file and produce surprising state.
	auditMu.Lock()
	if auditFile != nil {
		auditFile.Close()
		auditFile = nil
	}
	auditMu.Unlock()
	if err := os.Rename(logPath, rotPath); err != nil {
		t.Fatalf("manual rotate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := AppendAudit(AuditEvent{Action: ActionList, Message: fmt.Sprintf("post-%d", i)}); err != nil {
			t.Fatalf("AppendAudit post: %v", err)
		}
	}

	lines, err := tailAudit(100)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5: %v", len(lines), lines)
	}
	seen := make(map[string]int, len(lines))
	for _, l := range lines {
		seen[l]++
	}
	for l, c := range seen {
		if c > 1 {
			t.Fatalf("duplicate line across rotation: %q (count=%d)", l, c)
		}
	}
}

// TestTailAudit_RefusesSymlinkedLockFile verifies that tailAudit's reader-side
// open of audit.lock honors O_NOFOLLOW (the writer path is covered by
// TestEnsureAuditLockFile_RefusesSymlink). Without this guard, a hostile
// symlink at audit.lock could trick the reader into touching an attacker-
// controlled path through the reader fd.
func TestTailAudit_RefusesSymlinkedLockFile(t *testing.T) {
	tmp := withAuditTmpDir(t)
	dir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(tmp, "evil-lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	lockPath := filepath.Join(dir, "audit.lock")
	if err := os.Symlink(target, lockPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := tailAudit(10)
	if err == nil {
		t.Fatal("expected tailAudit to refuse symlinked audit.lock, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink-refusal error, got: %v", err)
	}
}

// TestTailAudit_NoDuplicatesUnderConcurrentRotation_MultiProcess proves that
// the FRESH-fd LOCK_SH in tailAudit is doing real work across process
// boundaries. The in-process variant of this test (above) cannot detect
// removal of the cross-process flock because auditMu alone serializes
// readers and writers within a single process. Here the writer runs in a
// different process; only the lock-file flock can prevent its rotation
// from interleaving with the parent's tailAudit reads.
//
// If the fresh-fd syscall.Flock(LOCK_SH) in tailAudit is removed, this
// test fails by detecting duplicate JSON lines in a single tailAudit
// result (the same physical inode read once as audit.log and once as
// audit.log.1 across the rotation window).
func TestTailAudit_NoDuplicatesUnderConcurrentRotation_MultiProcess(t *testing.T) {
	tmp := t.TempDir()
	// Reset in-process audit state so the parent process opens fresh fds
	// against the temp XDG_STATE_HOME path.
	t.Setenv("XDG_STATE_HOME", tmp)
	auditMu.Lock()
	if auditFile != nil {
		auditFile.Close()
		auditFile = nil
	}
	if auditLockFile != nil {
		auditLockFile.Close()
		auditLockFile = nil
	}
	auditWarnOnce = sync.Once{}
	auditMu.Unlock()

	bin := os.Args[0]
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("cannot stat test binary %q: %v", bin, err)
	}

	const hammerMs = 500
	const rotateBytes = 4096

	c := exec.Command(bin)
	c.Env = append(
		filterEnvOut(os.Environ(),
			"XDG_STATE_HOME",
			"OPQ_TEST_AUDIT_HAMMER",
			"OPQ_TEST_TAIL_HAMMER_WRITER",
			"OPQ_TEST_ROTATE_BYTES",
			"OPQ_TEST_TAIL_HAMMER_MS",
		),
		"OPQ_TEST_TAIL_HAMMER_WRITER=1",
		"XDG_STATE_HOME="+tmp,
		fmt.Sprintf("OPQ_TEST_ROTATE_BYTES=%d", rotateBytes),
		fmt.Sprintf("OPQ_TEST_TAIL_HAMMER_MS=%d", hammerMs),
	)
	if err := c.Start(); err != nil {
		t.Fatalf("start writer subprocess: %v", err)
	}

	// Reader loop in the parent: hammer tailAudit until either we observe
	// a duplicate (failure), the subprocess exits, or the wall-clock
	// budget elapses (whichever comes first).
	deadline := time.Now().Add(time.Duration(hammerMs+500) * time.Millisecond)
	var (
		iterations     int
		duplicateLines []string
		readErr        error
	)
	for time.Now().Before(deadline) {
		lines, err := tailAudit(200)
		if err != nil {
			// Lock-file may not exist before the writer's very first
			// write; tolerate a brief startup window.
			if strings.Contains(err.Error(), "no such file") {
				time.Sleep(time.Millisecond)
				continue
			}
			readErr = err
			break
		}
		iterations++
		seen := make(map[string]struct{}, len(lines))
		for _, l := range lines {
			if _, ok := seen[l]; ok {
				duplicateLines = append(duplicateLines, l)
			}
			seen[l] = struct{}{}
		}
		if len(duplicateLines) > 0 {
			break
		}
	}

	waitErr := c.Wait()

	if readErr != nil {
		t.Fatalf("reader error: %v", readErr)
	}
	if waitErr != nil {
		t.Fatalf("writer subprocess: %v", waitErr)
	}
	if iterations == 0 {
		t.Fatal("reader made zero successful iterations; test did not exercise tailAudit")
	}
	if len(duplicateLines) > 0 {
		t.Fatalf("tailAudit returned duplicate lines across cross-process rotation: %d duplicates, sample: %q",
			len(duplicateLines), duplicateLines[0])
	}

	// Sanity: rotation must have actually fired, otherwise this test did
	// not exercise the race window it claims to.
	if _, err := os.Stat(filepath.Join(tmp, "opq", "audit.log.1")); err != nil {
		t.Fatalf("expected audit.log.1 to exist (proving rotation occurred); stat: %v", err)
	}
}

// A process that already cached audit.log must follow another process's rotation.
func TestAppendAudit_ReopensAfterOtherProcessRotation(t *testing.T) {
	tmp := withAuditTmpDir(t)
	if err := AppendAudit(AuditEvent{Action: "test_rotation", Message: "before"}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(filterEnvOut(os.Environ(), "OPQ_TEST_AUDIT_ROTATE_ONCE"), "OPQ_TEST_AUDIT_ROTATE_ONCE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("other-process rotation: %v: %s", err, out)
	}
	if err := AppendAudit(AuditEvent{Action: "test_rotation", Message: "after"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmp, "opq", "audit.log")
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(active, []byte(`"msg":"after"`)) {
		t.Fatal("new event missing from active audit log after another process rotated it")
	}
	if bytes.Contains(rotated, []byte(`"msg":"after"`)) {
		t.Fatal("new event was written into the retired audit log")
	}
}

func BenchmarkAuditTail(b *testing.B) {
	root := b.TempDir()
	b.Setenv("XDG_STATE_HOME", root)
	dir := filepath.Join(root, "opq")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	line := []byte(`{"action":"bench","msg":"` + strings.Repeat("p", 180) + `"}` + "\n")
	for _, size := range []int{1 << 20, 10 << 20} {
		b.Run(fmt.Sprintf("MiB_%d", size>>20), func(b *testing.B) {
			f, err := os.Create(filepath.Join(dir, "audit.log"))
			if err != nil {
				b.Fatal(err)
			}
			for n := 0; n < size; n += len(line) {
				if _, err := f.Write(line); err != nil {
					f.Close()
					b.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := tailAudit(20); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestTailAudit_BackwardReadRecordBoundaries(t *testing.T) {
	long := strings.Repeat("x", 2*8*1024+13)
	cases := []struct {
		name, data string
		n          int
		want       []string
	}{
		{name: "empty", n: 2},
		{name: "blank_only", data: "\n\n\n", n: 2},
		{name: "unterminated", data: "older\nnewest", n: 1, want: []string{"newest"}},
		{name: "trailing_blanks", data: "older\nnewest\n\n\n", n: 1, want: []string{"newest"}},
		{name: "interior_blanks", data: "a\n\nb\n\nc\n", n: 2, want: []string{"b", "c"}},
		{name: "more_than_available", data: "a\nb", n: 5, want: []string{"a", "b"}},
		{name: "zero_returns_all", data: "a\n\nb\n", n: 0, want: []string{"a", "b"}},
		{name: "negative_returns_all", data: "a\nb", n: -1, want: []string{"a", "b"}},
		{name: "skip_long_old_record", data: long + "\na\nb\n", n: 2, want: []string{"a", "b"}},
		{name: "selected_record_spans_blocks", data: "older\n" + long + "\nnewest", n: 2, want: []string{long, "newest"}},
		{name: "boundary_at_block_start", data: "older\n" + strings.Repeat("x", 8*1024-1), n: 1, want: []string{strings.Repeat("x", 8*1024-1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := withAuditTmpDir(t)
			dir := filepath.Join(tmp, "opq")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := tailAudit(tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("records=%d want=%d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("record[%d] differs (got %d bytes, want %d)", i, len(got[i]), len(tc.want[i]))
				}
			}
		})
	}
}

func TestTailAudit_RejectsOversizeFileBeforeTail(t *testing.T) {
	for _, n := range []int{0, 1} {
		t.Run(fmt.Sprintf("n_%d", n), func(t *testing.T) {
			tmp := withAuditTmpDir(t)
			dir := filepath.Join(tmp, "opq")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(filepath.Join(dir, "audit.log"))
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(auditReadCap + 1); err != nil {
				f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := tailAudit(n); err == nil || !strings.Contains(err.Error(), "too large") {
				t.Fatalf("expected size refusal, got %v", err)
			}
		})
	}
}

func TestAppendAudit_CachedFileRejectsReplacementSymlink(t *testing.T) {
	tmp := withAuditTmpDir(t)
	if err := AppendAudit(AuditEvent{Action: "test_rotation", Message: "before"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmp, "opq", "audit.log")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := AppendAudit(AuditEvent{Action: "test_rotation", Message: "after"}); err == nil {
		t.Fatal("cached writer accepted a symlink replacement")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "untouched" {
		t.Fatal("symlink target was changed")
	}
}

func FuzzAuditTailMatchesFullRead(f *testing.F) {
	f.Add([]byte("a\n\nb\nc\n"), uint8(2))
	f.Add([]byte(strings.Repeat("x", 20*1024)+"\nnewest"), uint8(1))
	f.Add([]byte("\n\n"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, requested uint8) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		file, err := os.CreateTemp(t.TempDir(), "audit-tail-")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := file.Write(data); err != nil {
			t.Fatal(err)
		}
		n := int(requested) + 1
		got, err := readAuditTail(file, int64(len(data)), n)
		if err != nil {
			t.Fatal(err)
		}
		want := splitAuditLines(data)
		if len(want) > n {
			want = want[len(want)-n:]
		}
		if !slices.Equal(got, want) {
			t.Fatalf("backward tail differs from full read: got %d records, want %d", len(got), len(want))
		}
	})
}

func TestAuditContext_ContendedLocksRespectDeadline(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context) error
	}{
		{"append", func(ctx context.Context) error {
			return AppendAuditContext(ctx, AuditEvent{Action: "context_test", Message: "must-not-be-written"})
		}},
		{"tail", func(ctx context.Context) error { _, err := tailAuditContext(ctx, 20); return err }},
	}
	for _, operation := range operations {
		for _, kind := range []string{"mutex", "flock"} {
			t.Run(operation.name+"/"+kind, func(t *testing.T) {
				withAuditTmpDir(t)
				if err := AppendAudit(AuditEvent{Action: "context_test", Message: "before"}); err != nil {
					t.Fatal(err)
				}
				path, err := auditLogPath()
				if err != nil {
					t.Fatal(err)
				}
				var unlock func()
				if kind == "mutex" {
					auditMu.Lock()
					unlock = sync.OnceFunc(auditMu.Unlock)
				} else {
					holder, err := os.OpenFile(filepath.Join(filepath.Dir(path), auditLockFileName), os.O_RDWR, 0600)
					if err != nil {
						t.Fatal(err)
					}
					defer holder.Close()
					if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
						t.Fatal(err)
					}
					unlock = sync.OnceFunc(func() { syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) })
				}
				// Release eventually even if a regression blocks, so this test reports a
				// bounded failure rather than hanging the entire suite.
				rescue := time.AfterFunc(time.Second, unlock)
				defer func() { rescue.Stop(); unlock() }()
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				start := time.Now()
				err = operation.run(ctx)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error=%v, want deadline", err)
				}
				if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
					t.Fatalf("audit lock wait exceeded deadline: %v", elapsed)
				}
				unlock()
				if err := AppendAudit(AuditEvent{Action: "context_test", Message: "after"}); err != nil {
					t.Fatalf("lock leaked after cancellation: %v", err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte("must-not-be-written")) {
					t.Fatal("canceled append wrote an event after its lock wait")
				}
			})
		}
	}
}

func TestAuditContext_AlreadyCanceled(t *testing.T) {
	withAuditTmpDir(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := AppendAuditContext(ctx, AuditEvent{Action: "must-not-be-written"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("append error=%v", err)
	}
	if _, err := tailAuditContext(ctx, 20); !errors.Is(err, context.Canceled) {
		t.Fatalf("tail error=%v", err)
	}
	path, err := auditLogPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("canceled audit created a log: %v", err)
	}
}

func TestAuditContext_CancellationPreservesStorageWarning(t *testing.T) {
	withAuditTmpDir(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := AppendAuditContext(ctx, AuditEvent{Action: "canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	warningAvailable := false
	auditWarnOnce.Do(func() { warningAvailable = true })
	if !warningAvailable {
		t.Fatal("expected cancellation consumed warning for real audit storage errors")
	}
}
