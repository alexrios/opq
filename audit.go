package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is one line in the audit log. Designed to be JSON-stable so it
// can be tailed and parsed by other tools.
type AuditEvent struct {
	Timestamp  time.Time `json:"ts"`
	Action     string    `json:"action"`
	SecretName string    `json:"secret_name,omitempty"`
	Caller     string    `json:"caller,omitempty"`
	PID        int       `json:"pid"`
	PPID       int       `json:"ppid"`
	Message    string    `json:"msg,omitempty"`
}

// Audit actions.
const (
	ActionGet               = "get"
	ActionSet               = "set"
	ActionDelete            = "delete"
	ActionList              = "list"
	ActionExecInject        = "exec_inject"
	ActionMCPRun            = "mcp_run"
	ActionDenied            = "denied"
	ActionRedactionDisabled = "redaction_disabled"
)

var (
	auditMu   sync.Mutex
	auditFile *os.File
)

// auditLogPath returns ${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log.
func auditLogPath() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home: %w", err)
		}
		dir = filepath.Join(home, ".local", "state")
	}
	dir = filepath.Join(dir, "opq")
	return filepath.Join(dir, "audit.log"), nil
}

// openAuditFile opens the audit log in append-only mode with 0600 perms,
// creating the directory if needed. The returned file is shared across
// AppendAudit calls via a package-level mutex.
func openAuditFile() (*os.File, error) {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile != nil {
		return auditFile, nil
	}
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	// Defensive: if the file existed with looser perms, tighten them.
	_ = os.Chmod(path, 0o600)
	auditFile = f
	return f, nil
}

// AppendAudit writes one JSON-line event. Errors are returned but never
// fatal at the call site — auditing must not block the primary operation;
// callers may log the error and continue.
func AppendAudit(ev AuditEvent) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.PID == 0 {
		ev.PID = os.Getpid()
	}
	if ev.PPID == 0 {
		ev.PPID = os.Getppid()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	line = append(line, '\n')

	f, err := openAuditFile()
	if err != nil {
		return err
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// tailAudit returns the last n lines of the audit log as raw JSON strings.
// Reads the entire file (audit logs stay small for an interactive tool); if
// growth becomes a problem, switch to a reverse-seek implementation.
func tailAudit(n int) ([]string, error) {
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
