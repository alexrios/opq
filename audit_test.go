package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
