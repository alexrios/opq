package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
		for seq := 0; time.Now().Before(deadline); seq++ {
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
		// all) must unmarshal cleanly with empty Nonce — the strip
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
		// Active log has 3 entries; ask for 2 — answer must come
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
	// to descend into .log.1 — which is a symlink we must refuse.
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
// os.Environ() does NOT supersede an earlier occurrence — libc's
// getenv returns the first match — so the test's intended value is
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
			_ = AppendAudit(AuditEvent{
				Action:  ActionList,
				Message: fmt.Sprintf("seq-%d-%s", seq, pad),
			})
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

	// Bounded wall-clock budget: fast and deterministic.
	<-time.After(200 * time.Millisecond)
	close(stop)
	wg.Wait()

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
// different process — only the lock-file flock can prevent its rotation
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

