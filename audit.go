package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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
	ActionNetworkAllowed    = "network_allowed"
)

// auditRotateThreshold is the size in bytes at which the active audit log is
// renamed to audit.log.1 and a fresh file is opened. Only one historical
// rotation is kept; on rotation, any existing .log.1 is overwritten.
const auditRotateThreshold = 10 * 1024 * 1024 // 10 MiB

var (
	auditMu        sync.Mutex
	auditFile      *os.File
	auditWarnOnce  sync.Once
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

// prepareAuditDir creates and tightens the audit-log parent directory. It
// refuses to operate on symlinks or non-directories and uses fchmod on an
// O_NOFOLLOW|O_DIRECTORY fd to avoid the Lstat->Chmod TOCTOU race.
func prepareAuditDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	// Pre-check: if the bare path is a symlink (even one pointing to a
	// directory), refuse explicitly. With O_NOFOLLOW|O_DIRECTORY, the open
	// below returns ENOTDIR rather than ELOOP for a symlink-to-dir, which is
	// a less obvious diagnostic.
	if li, err := os.Lstat(dir); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit dir %q is a symlink, refusing", dir)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("audit dir %q is a symlink, refusing", dir)
		}
		if errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("audit dir %q is not a directory, refusing", dir)
		}
		return fmt.Errorf("open audit dir: %w", err)
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat audit dir: %w", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("audit dir %q is not a directory, refusing", dir)
	}
	// Tighten pre-existing wide permissions via the open fd (no path race).
	if err := syscall.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("fchmod audit dir: %w", err)
	}
	return nil
}

// rotateIfTooLargeLocked checks the size of the open audit file and, if it
// exceeds the threshold, closes it, renames it to <path>.1 (atomically
// overwriting any existing .1), and reopens a fresh file. Must be called
// with auditMu held.
func rotateIfTooLargeLocked(path string) error {
	if auditFile == nil {
		return nil
	}
	info, err := auditFile.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Size() < auditRotateThreshold {
		return nil
	}
	if err := auditFile.Close(); err != nil {
		// Best-effort: clear and continue; reopen will fail loudly if path is wedged.
		auditFile = nil
		return fmt.Errorf("close audit log for rotation: %w", err)
	}
	auditFile = nil
	// Rename is atomic on POSIX and overwrites the destination.
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}
	f, err := openAuditFileLocked(path)
	if err != nil {
		return err
	}
	auditFile = f
	return nil
}

// openAuditFileLocked opens the audit log file at path with the hardened
// flag set and tightens its mode via fchmod. Must be called with auditMu held.
func openAuditFileLocked(path string) (*os.File, error) {
	flags := os.O_APPEND | os.O_CREATE | os.O_WRONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit log %q is a symlink, refusing to write", path)
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	// Tighten pre-existing wide perms via fd (no path TOCTOU).
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fchmod audit log: %w", err)
	}
	return f, nil
}

// openAuditFile opens (and caches) the audit log. Returns the cached handle
// after the first successful call. Uses O_NOFOLLOW and fchmod to avoid
// symlink-swap and TOCTOU races.
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
	if err := prepareAuditDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := openAuditFileLocked(path)
	if err != nil {
		return nil, err
	}
	auditFile = f
	return f, nil
}

// appendAuditInternal performs the actual write. Split out so AppendAudit can
// own the sync.Once warning policy without duplicating error paths.
func appendAuditInternal(ev AuditEvent) error {
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

	if _, err := openAuditFile(); err != nil {
		return err
	}
	path, err := auditLogPath()
	if err != nil {
		return err
	}

	auditMu.Lock()
	defer auditMu.Unlock()
	// Check size before each write — long-running processes (MCP server) hold
	// the fd open for the whole process lifetime.
	if err := rotateIfTooLargeLocked(path); err != nil {
		return err
	}
	if auditFile == nil {
		return fmt.Errorf("audit log not open")
	}
	if _, err := auditFile.Write(line); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	// fsync after each write: secret-access events must survive crash/kill.
	if err := auditFile.Sync(); err != nil {
		return fmt.Errorf("fsync audit log: %w", err)
	}
	return nil
}

// AppendAudit writes one JSON-line event. The API contract is unchanged:
// callers may use `_ = AppendAudit(...)` and continue on error. On the FIRST
// error encountered in the process lifetime, a single loud warning is emitted
// to stderr so the operator notices that auditing is degraded.
func AppendAudit(ev AuditEvent) error {
	err := appendAuditInternal(ev)
	if err != nil {
		auditWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "opq: AUDIT LOG WRITE FAILED: %v. Subsequent audit failures will not be reported.\n", err)
		})
	}
	return err
}

// tailAudit returns the last n lines of the audit log as raw JSON strings.
// Reads the entire file (audit logs stay small for an interactive tool); if
// growth becomes a problem, switch to a reverse-seek implementation. Uses
// O_NOFOLLOW to refuse symlinked paths.
func tailAudit(n int) ([]string, error) {
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit log %q is a symlink, refusing to read", path)
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	data := make([]byte, info.Size())
	if _, err := f.Read(data); err != nil && info.Size() > 0 {
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
