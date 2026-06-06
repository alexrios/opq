// Package main — audit log writer.
//
// LOCKING (see TestAppendAudit_MultiprocessFlock). Writes are serialized by
// auditMu (in-process) and flock LOCK_EX (cross-process). The flock is held on a
// SEPARATE, never-rotated file (audit.lock), not on the audit.log fd: flock is
// fd-bound, and rotation closes/reopens audit.log, which would silently drop a
// lock held on it. The lock fd is opened once and outlives every rotation.
//
// tailAudit takes auditMu AND LOCK_SH on a FRESHLY-OPENED audit.lock fd across
// both reads (active + rotated), so a rotation between them can't make it read
// one inode twice (duplicate lines). The fd must be fresh because flock is
// per-open-file-description: two locks on the same fd don't compete, so a
// reader sharing the cached writer fd wouldn't block the writer's LOCK_EX.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// AuditEvent is one JSON line in the audit log, kept stable for external tools.
// Nonce is an optional per-call random tag a caller sets to find its own entry
// later (today only handleAuditTail, to strip its self-entry); never
// auto-generated. Legacy entries omit it via omitempty.
type AuditEvent struct {
	Timestamp   time.Time `json:"ts"`
	Action      string    `json:"action"`
	SecretName  string    `json:"secret_name,omitempty"`
	SecretNames []string  `json:"secret_names,omitempty"`
	Caller      string    `json:"caller,omitempty"`
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	Message     string    `json:"msg,omitempty"`
	Nonce       string    `json:"nonce,omitempty"`
}

// Audit actions.
const (
	ActionGet               = "get"
	ActionSet               = "set"
	ActionDelete            = "delete"
	ActionList              = "list"
	ActionExecInject        = "exec_inject"
	ActionMCPRun            = "mcp_run"
	ActionAuditTail         = "audit_tail"
	ActionDenied            = "denied"
	ActionRedactionDisabled = "redaction_disabled"
	ActionNetworkAllowed    = "network_allowed"
	ActionRevoke            = "revoke"
	ActionPrune             = "prune"
)

// Gate-failure reason taxonomy. Mirrors sanitizeBackendErr: only stable
// keys ever reach the operator-facing (and AI-readable via audit_tail)
// audit log Message. The user-facing error string keeps the verbose
// form.
const (
	GateReasonNoTTY           = "tty_open_failed"
	GateReasonTTYWrite        = "tty_write_failed"
	GateReasonTTYRead         = "tty_read_failed"
	GateReasonStdoutNoTTY     = "stdout_not_a_tty"
	GateReasonEnvMissing      = "missing_human_confirm_env"
	GateReasonConfirmMismatch = "confirmation_mismatch"
)

// auditRotateThreshold is the size in bytes at which the active audit log is
// renamed to audit.log.1 and a fresh file is opened. Only one historical
// rotation is kept; on rotation, any existing .log.1 is overwritten.
// Declared as var (not const) solely so race-condition tests can lower the
// threshold to trigger rotations on demand; production code must not mutate it.
var auditRotateThreshold int64 = 10 * 1024 * 1024 // 10 MiB

// auditLockFileName is the name (relative to the audit dir) of the
// rotation-immune lock file used for cross-process serialization.
const auditLockFileName = "audit.lock"

var (
	auditMu       sync.Mutex
	auditFile     *os.File
	auditLockFile *os.File
	auditWarnOnce sync.Once
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
	if err := syscall.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("fchmod audit dir: %w", err)
	}
	return nil
}

// rotateIfTooLargeLocked checks the size of the open audit file and, if it
// exceeds the threshold, closes it, renames it to <path>.1 (atomically
// overwriting any existing .1), and reopens a fresh file. Must be called
// with auditMu held AND with LOCK_EX on auditLockFile.
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
		auditFile = nil
		return fmt.Errorf("close audit log for rotation: %w", err)
	}
	auditFile = nil
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
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fchmod audit log: %w", err)
	}
	return f, nil
}

// ensureAuditFileLocked returns the cached audit-log fd, opening it if
// needed. Caller MUST hold auditMu.
func ensureAuditFileLocked() (*os.File, error) {
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

// ensureAuditLockFileLocked opens (and caches, process-global) the
// rotation-immune lock file used by writers for cross-process
// serialization. Caller MUST hold auditMu. The fd is intentionally
// never closed during process lifetime; O_CLOEXEC ensures it does not
// leak across exec. Readers use openAuditLockReaderLocked instead — see
// the note there about Linux flock semantics on the same
// open-file-description.
func ensureAuditLockFileLocked() (*os.File, error) {
	if auditLockFile != nil {
		return auditLockFile, nil
	}
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := prepareAuditDir(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, auditLockFileName)
	flags := os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	f, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit lock %q is a symlink, refusing", lockPath)
		}
		return nil, fmt.Errorf("open audit lock: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fchmod audit lock: %w", err)
	}
	auditLockFile = f
	return f, nil
}

// appendAuditInternal performs the actual write under auditMu + flock (see the
// package header for why the lock lives on a separate fd).
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

	path, err := auditLogPath()
	if err != nil {
		return err
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	lockFile, err := ensureAuditLockFileLocked()
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock audit lock: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	if _, err := ensureAuditFileLocked(); err != nil {
		return err
	}
	if err := rotateIfTooLargeLocked(path); err != nil {
		return err
	}
	if auditFile == nil {
		return fmt.Errorf("audit log not open")
	}
	if _, err := auditFile.Write(line); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
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

// auditReadCap bounds a single audit-file read. The active log is capped
// at auditRotateThreshold (10 MiB) and the rotated copy at the same; a
// healthy install will never approach this. Hitting the cap implies an
// externally planted or pre-rotation-bug file.
const auditReadCap = 32 * 1024 * 1024

// tailAudit returns the last n audit lines (active log, then prepending the
// rotated .log.1 if needed). Holds auditMu + LOCK_SH on a fresh lock fd across
// both reads — see the package header for the locking rationale.
func tailAudit(n int) ([]string, error) {
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	auditMu.Lock()
	defer auditMu.Unlock()

	readerLock, err := openAuditLockReaderLocked()
	if err != nil {
		return nil, err
	}
	// Close runs LAST (LIFO); LOCK_UN below must release the lock before the
	// fd is closed, otherwise Close would release it implicitly.
	defer readerLock.Close()
	if err := syscall.Flock(int(readerLock.Fd()), syscall.LOCK_SH); err != nil {
		return nil, fmt.Errorf("flock audit lock: %w", err)
	}
	defer syscall.Flock(int(readerLock.Fd()), syscall.LOCK_UN)

	lines, err := readAuditFileLinesLocked(path)
	if err != nil {
		return nil, err
	}
	if n > 0 && len(lines) >= n {
		return lines[len(lines)-n:], nil
	}
	rotated, err := readAuditFileLinesLocked(path + ".1")
	if err != nil {
		return nil, err
	}
	combined := append(rotated, lines...)
	if n > 0 && len(combined) > n {
		combined = combined[len(combined)-n:]
	}
	return combined, nil
}

// openAuditLockReaderLocked opens a FRESH lock-file fd for one read, so its
// LOCK_SH competes with the writer's LOCK_EX (see the package header). Caller
// holds auditMu and must close the returned fd.
func openAuditLockReaderLocked() (*os.File, error) {
	path, err := auditLogPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := prepareAuditDir(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, auditLockFileName)
	// O_RDONLY is sufficient for flock(LOCK_SH); Linux open(2) accepts
	// O_CREAT with O_RDONLY (the created file is empty and never written
	// through this fd — the lock is the only purpose).
	flags := os.O_CREATE | os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	f, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit lock %q is a symlink, refusing", lockPath)
		}
		return nil, fmt.Errorf("open audit lock: %w", err)
	}
	// fchmod for symmetry with the writer path (defends against an existing
	// lock file with looser perms; the create-mode only applies on creation).
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fchmod audit lock: %w", err)
	}
	return f, nil
}

// readAuditFileLinesLocked opens path with O_NOFOLLOW|O_CLOEXEC, reads up
// to auditReadCap bytes, and returns the split lines. Caller MUST already
// hold auditMu and LOCK_SH (or LOCK_EX) on a reader lock fd. A missing
// file returns (nil, nil); a file exceeding the cap returns an error.
func readAuditFileLinesLocked(path string) ([]string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit log %q is a symlink, refusing to read", path)
		}
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, auditReadCap+1))
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	if int64(len(data)) > auditReadCap {
		return nil, fmt.Errorf("audit log too large (>%d bytes), refusing to read", auditReadCap)
	}
	return splitAuditLines(data), nil
}

// sanitizeExecStartErr maps os/exec start errors to a fixed audit-log
// taxonomy. The wrapped error returned to the AI keeps the full text;
// only the audit Message is sanitized to prevent caller-controlled
// strings from polluting the operator-visible log.
func sanitizeExecStartErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "exec_not_found"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "exec_permission_denied"
	}
	return "exec_start_failed"
}

// splitAuditLines splits raw bytes into JSON-line records. Empty lines
// are dropped; a final unterminated line (if any) is kept.
func splitAuditLines(data []byte) []string {
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
	return lines
}
