package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type DoctorCmd struct {
	JSON bool `name:"json" help:"Output health check results as JSON."`
}

type doctorStatus string

const (
	doctorOK   doctorStatus = "OK"
	doctorWarn doctorStatus = "WARN"
	doctorFail doctorStatus = "FAIL"
)

type doctorCheck struct {
	Name        string       `json:"name"`
	Status      doctorStatus `json:"status"`
	Summary     string       `json:"summary"`
	Remediation []string     `json:"remediation,omitempty"`
	Details     any          `json:"details,omitempty"`
}

type doctorReport struct {
	Version string        `json:"version"`
	OS      string        `json:"os"`
	Arch    string        `json:"arch"`
	Healthy bool          `json:"healthy"`
	Checks  []doctorCheck `json:"checks"`
}

type doctorMetaCounts struct {
	Total         int `json:"total"`
	Active        int `json:"active"`
	Expiring      int `json:"expiring"`
	Expired       int `json:"expired"`
	Revoked       int `json:"revoked"`
	UpdatePending int `json:"update_pending"`
	MetaError     int `json:"meta_error"`
}

// doctorDeps injects external boundaries so unit tests can exercise every
// health check without touching the host keyring, sandbox binary, or user
// directories.
type doctorDeps struct {
	version         func() string
	goos            string
	goarch          string
	openBackend     func() (Backend, error)
	vaultDir        func() (string, error)
	legacyCount     func(context.Context) (int, error)
	verifySandbox   func() error
	auditLogPath    func() (string, error)
	policyLockDir   func() (string, error)
	rotateThreshold int64
	now             func() time.Time
	stdout          io.Writer
	isTTY           bool
	noColor         bool
}

func defaultDoctorDeps() doctorDeps {
	deps := doctorDeps{
		version:         resolveVersion,
		goos:            runtime.GOOS,
		goarch:          runtime.GOARCH,
		openBackend:     OpenDefaultBackend,
		verifySandbox:   VerifySandboxAvailable,
		auditLogPath:    auditLogPath,
		policyLockDir:   policyLockDir,
		rotateThreshold: auditRotateThreshold,
		now:             func() time.Time { return time.Now().UTC() },
		stdout:          os.Stdout,
		isTTY:           term.IsTerminal(int(os.Stdout.Fd())),
		noColor:         os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb",
	}
	if runtime.GOOS == "darwin" {
		deps.vaultDir = vaultDir
		deps.legacyCount = legacyKeychainCount
	}
	return deps
}

func (c *DoctorCmd) Run() error {
	return runDoctor(context.Background(), c.JSON, defaultDoctorDeps())
}

// runDoctor executes all health checks in read-only mode (never reading secret
// values and never creating state directories or audit logs), writes the report
// to deps.stdout, and returns an error if any critical check has status FAIL.
func runDoctor(ctx context.Context, asJSON bool, deps doctorDeps) error {
	if deps.version == nil {
		deps.version = resolveVersion
	}
	if deps.goos == "" {
		deps.goos = runtime.GOOS
	}
	if deps.goarch == "" {
		deps.goarch = runtime.GOARCH
	}
	if deps.rotateThreshold <= 0 {
		deps.rotateThreshold = auditRotateThreshold
	}
	if deps.now == nil {
		deps.now = func() time.Time { return time.Now().UTC() }
	}
	if deps.stdout == nil {
		deps.stdout = os.Stdout
	}

	ver := deps.version()
	binaryCheck := doctorCheckBinary(ver, deps.goos, deps.goarch)
	keyringCheck, backend, keys := doctorCheckKeyring(ctx, deps)
	sandboxCheck := doctorCheckSandbox(deps)
	auditCheck := doctorCheckAuditLog(deps)
	policyCheck, policyDir := doctorCheckPolicyLock(deps)
	metaCheck := doctorCheckMetadata(ctx, backend, keys, policyCheck.Status == doctorOK, policyDir, deps.now())

	checks := []doctorCheck{
		binaryCheck,
		keyringCheck,
	}
	if deps.vaultDir != nil {
		checks = append(checks, doctorCheckVault(deps))
	}
	checks = append(checks,
		sandboxCheck,
		auditCheck,
		policyCheck,
		metaCheck,
	)

	failCount := 0
	for _, ch := range checks {
		if ch.Status == doctorFail {
			failCount++
		}
	}

	report := doctorReport{
		Version: ver,
		OS:      deps.goos,
		Arch:    deps.goarch,
		Healthy: failCount == 0,
		Checks:  checks,
	}

	if asJSON {
		enc := json.NewEncoder(deps.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode doctor report: %w", err)
		}
	} else {
		if err := doctorRenderText(deps.stdout, report, deps.isTTY && !deps.noColor); err != nil {
			return err
		}
	}

	if failCount > 0 {
		return fmt.Errorf("doctor found %d failing %s", failCount, doctorPlural(failCount, "check", "checks"))
	}
	return nil
}

func doctorCheckBinary(ver, goos, goarch string) doctorCheck {
	return doctorCheck{
		Name:    "binary",
		Status:  doctorOK,
		Summary: fmt.Sprintf("opq %s (%s/%s)", ver, goos, goarch),
		Details: map[string]any{
			"version": ver,
			"os":      goos,
			"arch":    goarch,
		},
	}
}

func doctorCheckKeyring(ctx context.Context, deps doctorDeps) (doctorCheck, Backend, []string) {
	backend, err := deps.openBackend()
	if err != nil {
		return doctorCheck{
			Name:        "keyring",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("failed to open keyring: %v", err),
			Remediation: doctorKeyringRemediation(deps.goos, err),
		}, nil, nil
	}

	keys, err := backend.List(ctx)
	if err != nil {
		return doctorCheck{
			Name:        "keyring",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("%s opened, but listing keys failed: %v", backend.Name(), err),
			Remediation: doctorKeyringRemediation(deps.goos, err),
			Details: map[string]any{
				"backend": backend.Name(),
			},
		}, nil, nil
	}

	visible := filterVisibleSecretNames(keys)
	details := map[string]any{
		"backend":      backend.Name(),
		"secret_count": len(visible),
	}
	if deps.legacyCount != nil {
		if legacyN, lerr := deps.legacyCount(ctx); lerr == nil && legacyN > 0 {
			details["legacy_secret_count"] = legacyN
			return doctorCheck{
				Name:    "keyring",
				Status:  doctorWarn,
				Summary: fmt.Sprintf("%s (%d %s; %d legacy Keychain %s pending migration)", backend.Name(), len(visible), doctorPlural(len(visible), "secret", "secrets"), legacyN, doctorPlural(legacyN, "secret", "secrets")),
				Remediation: []string{
					fmt.Sprintf("%d legacy macOS Keychain %s will auto-migrate on first use, or run 'opq migrate [name...]' to migrate now", legacyN, doctorPlural(legacyN, "secret", "secrets")),
				},
				Details: details,
			}, backend, keys
		}
	}
	return doctorCheck{
		Name:    "keyring",
		Status:  doctorOK,
		Summary: fmt.Sprintf("%s (%d %s)", backend.Name(), len(visible), doctorPlural(len(visible), "secret", "secrets")),
		Details: details,
	}, backend, keys
}

func doctorCheckVault(deps doctorDeps) doctorCheck {
	dir, err := deps.vaultDir()
	if err != nil {
		return doctorCheck{
			Name:    "vault",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot resolve vault dir: %v", err),
		}
	}
	vaultPath := filepath.Join(dir, vaultFileName)

	li, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if cerr := doctorCheckCreatableDir(dir); cerr != nil {
				return doctorCheck{
					Name:        "vault",
					Status:      doctorFail,
					Summary:     fmt.Sprintf("vault dir %s cannot be created: %v", dir, cerr),
					Remediation: []string{fmt.Sprintf("ensure the parent of %s exists and is writable", dir)},
					Details: map[string]any{
						"path":      vaultPath,
						"dir":       dir,
						"exists":    false,
						"creatable": false,
					},
				}
			}
			return doctorCheck{
				Name:    "vault",
				Status:  doctorOK,
				Summary: fmt.Sprintf("%s (not created yet)", vaultPath),
				Details: map[string]any{
					"path":      vaultPath,
					"dir":       dir,
					"exists":    false,
					"creatable": true,
				},
			}
		}
		return doctorCheck{
			Name:    "vault",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect vault dir %s: %v", dir, err),
		}
	}

	if li.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault dir %s is a symlink (refused)", dir),
			Remediation: []string{fmt.Sprintf("remove symlink %s and create a regular 0700 directory", dir)},
		}
	}
	if !li.IsDir() {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault dir %s is not a directory", dir),
			Remediation: []string{fmt.Sprintf("remove or move %s so opq can create a 0700 directory", dir)},
		}
	}
	if perm := li.Mode().Perm(); perm != 0o700 {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault dir %s has mode %04o (expected 0700)", dir, perm),
			Remediation: []string{fmt.Sprintf("run 'chmod 700 %s'", dir)},
			Details: map[string]any{
				"path":     vaultPath,
				"dir":      dir,
				"dir_mode": fmt.Sprintf("%04o", perm),
			},
		}
	}

	lockPath := filepath.Join(dir, vaultLockName)
	if lfi, lerr := os.Lstat(lockPath); lerr == nil {
		if lfi.Mode()&os.ModeSymlink != 0 {
			return doctorCheck{
				Name:        "vault",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("vault lock %s is a symlink (refused)", lockPath),
				Remediation: []string{fmt.Sprintf("remove symlink %s", lockPath)},
			}
		}
		if !lfi.Mode().IsRegular() {
			return doctorCheck{
				Name:        "vault",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("vault lock %s is not a regular file", lockPath),
				Remediation: []string{fmt.Sprintf("remove non-regular file %s", lockPath)},
			}
		}
		if lperm := lfi.Mode().Perm(); lperm != 0o600 {
			return doctorCheck{
				Name:        "vault",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("vault lock %s has mode %04o (expected 0600)", lockPath, lperm),
				Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", lockPath)},
			}
		}
	} else if !os.IsNotExist(lerr) {
		return doctorCheck{
			Name:    "vault",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect vault lock %s: %v", lockPath, lerr),
		}
	}

	fi, err := os.Lstat(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{
				Name:    "vault",
				Status:  doctorOK,
				Summary: fmt.Sprintf("%s (not created yet)", vaultPath),
				Details: map[string]any{
					"path":     vaultPath,
					"dir":      dir,
					"dir_mode": "0700",
					"exists":   false,
				},
			}
		}
		return doctorCheck{
			Name:    "vault",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect vault file %s: %v", vaultPath, err),
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault file %s is a symlink (refused)", vaultPath),
			Remediation: []string{fmt.Sprintf("remove symlink %s", vaultPath)},
		}
	}
	if !fi.Mode().IsRegular() {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault file %s is not a regular file", vaultPath),
			Remediation: []string{fmt.Sprintf("remove non-regular file %s", vaultPath)},
		}
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return doctorCheck{
			Name:        "vault",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("vault file %s has mode %04o (expected 0600)", vaultPath, perm),
			Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", vaultPath)},
			Details: map[string]any{
				"path": vaultPath,
				"mode": fmt.Sprintf("%04o", perm),
			},
		}
	}
	if fi.Size() > vaultMaxFileSize {
		return doctorCheck{
			Name:    "vault",
			Status:  doctorFail,
			Summary: fmt.Sprintf("%s exceeds %s size limit (%s)", vaultPath, doctorFormatBytes(vaultMaxFileSize), doctorFormatBytes(fi.Size())),
		}
	}
	return doctorCheck{
		Name:    "vault",
		Status:  doctorOK,
		Summary: fmt.Sprintf("%s (mode 0600, %s)", vaultPath, doctorFormatBytes(fi.Size())),
		Details: map[string]any{
			"path":       vaultPath,
			"dir":        dir,
			"exists":     true,
			"dir_mode":   "0700",
			"mode":       "0600",
			"size_bytes": fi.Size(),
		},
	}
}

func doctorKeyringRemediation(goos string, err error) []string {
	msg := ""
	if err != nil {
		msg = strings.ToLower(err.Error())
	}
	switch goos {
	case "darwin":
		if strings.Contains(msg, "cgo") || strings.Contains(msg, "no available") || strings.Contains(msg, "not available") {
			return []string{
				"macOS Keychain requires a CGO-enabled build: install Xcode Command Line Tools ('xcode-select --install') and rebuild with CGO_ENABLED=1",
			}
		}
		return []string{
			"unlock your macOS login Keychain ('security unlock-keychain login.keychain-db') or open Keychain Access",
			"verify the 'opq-vault' master key exists in your login Keychain if vault.enc is already present",
		}
	case "linux":
		return []string{
			"ensure a Secret Service provider (gnome-keyring-daemon, KWallet, or KeePassXC) is running and unlocked",
			"verify DBUS_SESSION_BUS_ADDRESS is set in your shell (for headless sessions, wrap with 'dbus-run-session')",
		}
	default:
		return []string{
			"opq supports Linux Secret Service and macOS Keychain only",
		}
	}
}

func doctorCheckSandbox(deps doctorDeps) doctorCheck {
	label := doctorSandboxLabel(deps.goos)
	err := deps.verifySandbox()
	if err != nil {
		return doctorCheck{
			Name:        "sandbox",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("%s unavailable", label),
			Remediation: []string{err.Error()},
			Details: map[string]any{
				"backend":   label,
				"available": false,
				"error":     err.Error(),
			},
		}
	}
	return doctorCheck{
		Name:    "sandbox",
		Status:  doctorOK,
		Summary: fmt.Sprintf("%s available", label),
		Details: map[string]any{
			"backend":   label,
			"available": true,
		},
	}
}

func doctorSandboxLabel(goos string) string {
	switch goos {
	case "linux":
		return "bubblewrap (bwrap)"
	case "darwin":
		return "Seatbelt (sandbox-exec)"
	default:
		return fmt.Sprintf("unsupported (%s)", goos)
	}
}

func doctorCheckAuditLog(deps doctorDeps) doctorCheck {
	logPath, err := deps.auditLogPath()
	if err != nil {
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot resolve audit log path: %v", err),
		}
	}

	dir := filepath.Dir(logPath)
	li, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if cerr := doctorCheckCreatableDir(dir); cerr != nil {
				return doctorCheck{
					Name:        "audit_log",
					Status:      doctorFail,
					Summary:     fmt.Sprintf("audit dir %s cannot be created: %v", dir, cerr),
					Remediation: []string{fmt.Sprintf("ensure the parent of %s exists and is writable, or set XDG_STATE_HOME to a writable path", dir)},
					Details: map[string]any{
						"path":      logPath,
						"dir":       dir,
						"exists":    false,
						"creatable": false,
					},
				}
			}
			return doctorCheck{
				Name:    "audit_log",
				Status:  doctorOK,
				Summary: fmt.Sprintf("%s (not created yet)", logPath),
				Details: map[string]any{
					"path":                   logPath,
					"dir":                    dir,
					"exists":                 false,
					"creatable":              true,
					"rotate_threshold_bytes": deps.rotateThreshold,
				},
			}
		}
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect audit dir %s: %v", dir, err),
		}
	}

	if li.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit dir %s is a symlink (refused)", dir),
			Remediation: []string{fmt.Sprintf("remove symlink %s and create a regular 0700 directory", dir)},
		}
	}
	if !li.IsDir() {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit dir %s is not a directory", dir),
			Remediation: []string{fmt.Sprintf("remove or move %s so opq can create a 0700 directory", dir)},
		}
	}
	if perm := li.Mode().Perm(); perm != 0o700 {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit dir %s has mode %04o (expected 0700)", dir, perm),
			Remediation: []string{fmt.Sprintf("run 'chmod 700 %s'", dir)},
			Details: map[string]any{
				"path":     logPath,
				"dir":      dir,
				"dir_mode": fmt.Sprintf("%04o", perm),
			},
		}
	}

	// Check audit.lock if present (read-only).
	lockPath := filepath.Join(dir, auditLockFileName)
	if lfi, lerr := os.Lstat(lockPath); lerr == nil {
		if lfi.Mode()&os.ModeSymlink != 0 {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("audit lock %s is a symlink (refused)", lockPath),
				Remediation: []string{fmt.Sprintf("remove symlink %s", lockPath)},
			}
		}
		if !lfi.Mode().IsRegular() {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("audit lock %s is not a regular file", lockPath),
				Remediation: []string{fmt.Sprintf("remove non-regular file %s", lockPath)},
			}
		}
		if lperm := lfi.Mode().Perm(); lperm != 0o600 {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("audit lock %s has mode %04o (expected 0600)", lockPath, lperm),
				Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", lockPath)},
			}
		}
	} else if !os.IsNotExist(lerr) {
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect audit lock %s: %v", lockPath, lerr),
		}
	}

	// Check rotated audit.log.1 if present (read-only).
	rotPath := logPath + ".1"
	if rfi, rerr := os.Lstat(rotPath); rerr == nil {
		if rfi.Mode()&os.ModeSymlink != 0 {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("rotated audit log %s is a symlink (refused)", rotPath),
				Remediation: []string{fmt.Sprintf("remove symlink %s", rotPath)},
			}
		}
		if !rfi.Mode().IsRegular() {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("rotated audit log %s is not a regular file", rotPath),
				Remediation: []string{fmt.Sprintf("remove non-regular file %s", rotPath)},
			}
		}
		if rperm := rfi.Mode().Perm(); rperm&0o077 != 0 {
			return doctorCheck{
				Name:        "audit_log",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("rotated audit log %s has mode %04o (expected 0600)", rotPath, rperm),
				Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", rotPath)},
			}
		}
	} else if !os.IsNotExist(rerr) {
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect rotated audit log %s: %v", rotPath, rerr),
		}
	}

	fi, err := os.Lstat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return doctorCheck{
				Name:    "audit_log",
				Status:  doctorOK,
				Summary: fmt.Sprintf("%s (not created yet)", logPath),
				Details: map[string]any{
					"path":                   logPath,
					"dir":                    dir,
					"dir_mode":               "0700",
					"exists":                 false,
					"rotate_threshold_bytes": deps.rotateThreshold,
				},
			}
		}
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect audit log %s: %v", logPath, err),
		}
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit log %s is a symlink (refused)", logPath),
			Remediation: []string{fmt.Sprintf("remove symlink %s so opq can create a regular 0600 log file", logPath)},
		}
	}
	if !fi.Mode().IsRegular() {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit log %s is not a regular file", logPath),
			Remediation: []string{fmt.Sprintf("remove non-regular file %s", logPath)},
		}
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("audit log %s has mode %04o (expected 0600)", logPath, perm),
			Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", logPath)},
			Details: map[string]any{
				"path": logPath,
				"mode": fmt.Sprintf("%04o", perm),
			},
		}
	}

	size := fi.Size()
	details := map[string]any{
		"path":                   logPath,
		"dir":                    dir,
		"exists":                 true,
		"dir_mode":               "0700",
		"mode":                   "0600",
		"size_bytes":             size,
		"rotate_threshold_bytes": deps.rotateThreshold,
	}

	if size > auditReadCap {
		return doctorCheck{
			Name:        "audit_log",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("%s exceeds %s read cap (%s)", logPath, doctorFormatBytes(auditReadCap), doctorFormatBytes(size)),
			Remediation: []string{fmt.Sprintf("archive or rotate %s (opq refuses to read audit files over %s)", logPath, doctorFormatBytes(auditReadCap))},
			Details:     details,
		}
	}
	if size >= deps.rotateThreshold {
		return doctorCheck{
			Name:    "audit_log",
			Status:  doctorWarn,
			Summary: fmt.Sprintf("%s (mode 0600, %s / %s rotation threshold; will rotate on next write)", logPath, doctorFormatBytes(size), doctorFormatBytes(deps.rotateThreshold)),
			Details: details,
		}
	}
	return doctorCheck{
		Name:    "audit_log",
		Status:  doctorOK,
		Summary: fmt.Sprintf("%s (mode 0600, %s / %s rotation threshold)", logPath, doctorFormatBytes(size), doctorFormatBytes(deps.rotateThreshold)),
		Details: details,
	}
}

func doctorCheckPolicyLock(deps doctorDeps) (doctorCheck, string) {
	dir, err := deps.policyLockDir()
	if err != nil {
		return doctorCheck{
			Name:    "policy_lock",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot resolve policy lock dir: %v", err),
		}, ""
	}

	li, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if cerr := doctorCheckCreatableDir(dir); cerr != nil {
				return doctorCheck{
					Name:        "policy_lock",
					Status:      doctorFail,
					Summary:     fmt.Sprintf("policy lock dir %s cannot be created: %v", dir, cerr),
					Remediation: []string{fmt.Sprintf("ensure the parent of %s exists and is writable", dir)},
					Details: map[string]any{
						"dir":       dir,
						"exists":    false,
						"creatable": false,
					},
				}, dir
			}
			return doctorCheck{
				Name:    "policy_lock",
				Status:  doctorOK,
				Summary: fmt.Sprintf("%s (not created yet)", dir),
				Details: map[string]any{
					"dir":       dir,
					"exists":    false,
					"creatable": true,
				},
			}, dir
		}
		return doctorCheck{
			Name:    "policy_lock",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect policy lock dir %s: %v", dir, err),
		}, dir
	}

	if li.Mode()&os.ModeSymlink != 0 {
		return doctorCheck{
			Name:        "policy_lock",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("policy lock dir %s is a symlink (refused)", dir),
			Remediation: []string{fmt.Sprintf("remove symlink %s and create a regular 0700 directory", dir)},
		}, dir
	}
	if !li.IsDir() {
		return doctorCheck{
			Name:        "policy_lock",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("policy lock dir %s is not a directory", dir),
			Remediation: []string{fmt.Sprintf("remove or move %s so opq can create a 0700 directory", dir)},
		}, dir
	}
	if perm := li.Mode().Perm(); perm != 0o700 {
		return doctorCheck{
			Name:        "policy_lock",
			Status:      doctorFail,
			Summary:     fmt.Sprintf("policy lock dir %s has mode %04o (expected 0700)", dir, perm),
			Remediation: []string{fmt.Sprintf("run 'chmod 700 %s'", dir)},
			Details: map[string]any{
				"dir":      dir,
				"dir_mode": fmt.Sprintf("%04o", perm),
			},
		}, dir
	}

	lockPath := filepath.Join(dir, "policy.lock")
	if fi, lerr := os.Lstat(lockPath); lerr == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return doctorCheck{
				Name:        "policy_lock",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("policy lock %s is a symlink (refused)", lockPath),
				Remediation: []string{fmt.Sprintf("remove symlink %s", lockPath)},
			}, dir
		}
		if !fi.Mode().IsRegular() {
			return doctorCheck{
				Name:        "policy_lock",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("policy lock %s is not a regular file", lockPath),
				Remediation: []string{fmt.Sprintf("remove non-regular file %s", lockPath)},
			}, dir
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			return doctorCheck{
				Name:        "policy_lock",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("policy lock %s has mode %04o (expected 0600)", lockPath, perm),
				Remediation: []string{fmt.Sprintf("run 'chmod 600 %s'", lockPath)},
				Details: map[string]any{
					"dir":       dir,
					"lock_path": lockPath,
					"lock_mode": fmt.Sprintf("%04o", perm),
				},
			}, dir
		}
	} else if !os.IsNotExist(lerr) {
		return doctorCheck{
			Name:    "policy_lock",
			Status:  doctorFail,
			Summary: fmt.Sprintf("cannot inspect policy lock %s: %v", lockPath, lerr),
		}, dir
	}

	return doctorCheck{
		Name:    "policy_lock",
		Status:  doctorOK,
		Summary: fmt.Sprintf("%s (mode 0700)", dir),
		Details: map[string]any{
			"dir":      dir,
			"exists":   true,
			"dir_mode": "0700",
		},
	}, dir
}

func doctorCheckMetadata(ctx context.Context, backend Backend, keys []string, policyLockHealthy bool, policyDir string, now time.Time) doctorCheck {
	if backend == nil {
		return doctorCheck{
			Name:    "secret_metadata",
			Status:  doctorWarn,
			Summary: "skipped (keyring unavailable)",
		}
	}

	// Acquire a read-only shared lock only if policy.lock already exists so
	// doctor stays non-destructive on a fresh install while avoiding torn reads
	// against concurrent writers on an active install.
	if policyLockHealthy && policyDir != "" {
		unlock, err := doctorTryReadOnlyPolicyLock(ctx, filepath.Join(policyDir, "policy.lock"))
		if err != nil {
			return doctorCheck{
				Name:        "secret_metadata",
				Status:      doctorFail,
				Summary:     fmt.Sprintf("failed to acquire read-only policy lock: %v", err),
				Remediation: []string{fmt.Sprintf("check permissions and active locks on %s", filepath.Join(policyDir, "policy.lock"))},
			}
		}
		defer unlock()
	}

	seen := make(map[string]bool, len(keys))
	var names []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, k := range keys {
		if name, ok := secretNameFromMetaKey(k); ok {
			add(name)
		} else {
			add(k)
		}
	}
	sort.Strings(names)

	var counts doctorMetaCounts
	counts.Total = len(names)
	for _, n := range names {
		// loadMeta only ever reads "meta/<n>", never the secret value key.
		m, err := loadMeta(ctx, backend, n)
		switch {
		case err != nil:
			counts.MetaError++
		case m != nil && m.Pending:
			counts.UpdatePending++
		case m.IsRevoked():
			counts.Revoked++
		case m.IsExpiredAt(now):
			counts.Expired++
		default:
			counts.Active++
			if m.HasExpiry() {
				counts.Expiring++
			}
		}
	}

	var remediation []string
	if counts.UpdatePending > 0 {
		remediation = append(remediation, fmt.Sprintf("%d UPDATE-PENDING: retry 'opq set <name>' or remove with 'opq delete <name>'", counts.UpdatePending))
	}
	if counts.MetaError > 0 {
		remediation = append(remediation, fmt.Sprintf("%d meta-error: inspect with 'opq list' and clear corrupt metadata with 'opq delete <name>'", counts.MetaError))
	}
	if counts.Expired > 0 {
		remediation = append(remediation, fmt.Sprintf("%d EXPIRED: run 'opq prune' to delete expired secrets (use 'opq prune --dry-run' to preview)", counts.Expired))
	}
	if counts.Revoked > 0 {
		remediation = append(remediation, fmt.Sprintf("%d REVOKED: tombstone retained; remove with 'opq delete <name>' or 'opq prune --include-revoked'", counts.Revoked))
	}

	hasWarnings := counts.UpdatePending > 0 || counts.MetaError > 0 || counts.Expired > 0
	status := doctorOK
	if hasWarnings {
		status = doctorWarn
	}

	var summary string
	if counts.Total == 0 {
		summary = "no secrets stored"
	} else if !hasWarnings && counts.Revoked == 0 {
		summary = fmt.Sprintf("%d active %s, all metadata healthy", counts.Active, doctorPlural(counts.Active, "secret", "secrets"))
	} else {
		var parts []string
		parts = append(parts, fmt.Sprintf("%d active", counts.Active))
		if counts.UpdatePending > 0 {
			parts = append(parts, fmt.Sprintf("%d UPDATE-PENDING", counts.UpdatePending))
		}
		if counts.MetaError > 0 {
			parts = append(parts, fmt.Sprintf("%d meta-error", counts.MetaError))
		}
		if counts.Expired > 0 {
			parts = append(parts, fmt.Sprintf("%d EXPIRED", counts.Expired))
		}
		if counts.Revoked > 0 {
			parts = append(parts, fmt.Sprintf("%d REVOKED", counts.Revoked))
		}
		summary = strings.Join(parts, ", ")
	}

	return doctorCheck{
		Name:        "secret_metadata",
		Status:      status,
		Summary:     summary,
		Remediation: remediation,
		Details:     counts,
	}
}

// doctorCheckCreatableDir verifies that a non-existent directory has an
// existing, writable ancestor directory without modifying the filesystem.
func doctorCheckCreatableDir(dir string) error {
	cur := filepath.Clean(dir)
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return fmt.Errorf("no existing parent directory found for %q", dir)
		}
		li, lerr := os.Lstat(parent)
		if lerr == nil {
			if li.Mode()&os.ModeSymlink != 0 {
				// Ancestors like /var -> /private/var on macOS are normal; follow
				// to verify the target exists and is a writable directory, but fail
				// on a dangling symlink.
				st, err := os.Stat(parent)
				if err != nil {
					if os.IsNotExist(err) {
						return fmt.Errorf("ancestor %q is a dangling symlink", parent)
					}
					return fmt.Errorf("cannot inspect ancestor %q: %w", parent, err)
				}
				if !st.IsDir() {
					return fmt.Errorf("ancestor %q is not a directory", parent)
				}
			} else if !li.IsDir() {
				return fmt.Errorf("ancestor %q is not a directory", parent)
			}
			if err := unix.Access(parent, unix.W_OK|unix.X_OK); err != nil {
				return fmt.Errorf("ancestor %q is not writable: %w", parent, err)
			}
			return nil
		}
		if !os.IsNotExist(lerr) {
			return fmt.Errorf("cannot inspect ancestor %q: %w", parent, lerr)
		}
		cur = parent
	}
}

// doctorTryReadOnlyPolicyLock acquires LOCK_SH on an already-existing
// policy.lock without creating or chmodding anything. If the file does not
// exist yet, it returns a no-op unlock function and nil error.
func doctorTryReadOnlyPolicyLock(ctx context.Context, lockPath string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return func() {}, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("policy lock %q is a symlink", lockPath)
		}
		return nil, err
	}
	fail := func(err error) (func(), error) { _ = f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !st.Mode().IsRegular() {
		return fail(errors.New("policy lock is not a regular file"))
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return fail(fmt.Errorf("flock policy lock: %w", err))
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(ctx.Err())
		case <-timer.C:
		}
	}
}

func doctorRenderText(w io.Writer, report doctorReport, useColor bool) error {
	// Pad by plain visible width before applying ANSI SGR codes so check rows
	// and remediation rows stay strictly aligned whether color is enabled or not.
	const colGap = "  "
	badgeWidth := len("[FAIL]")
	nameWidth := len("->")
	for _, ch := range report.Checks {
		if l := len(ch.Status) + 2; l > badgeWidth {
			badgeWidth = l
		}
		if l := len(ch.Name); l > nameWidth {
			nameWidth = l
		}
	}

	blankBadge := strings.Repeat(" ", badgeWidth)
	arrowPad := strings.Repeat(" ", nameWidth-len("->"))

	for _, ch := range report.Checks {
		plainBadgeLen := len(ch.Status) + 2
		badge := doctorStatusBadge(ch.Status, useColor) + strings.Repeat(" ", badgeWidth-plainBadgeLen)
		name := ch.Name + strings.Repeat(" ", nameWidth-len(ch.Name))
		if _, err := fmt.Fprintf(w, "%s%s%s%s%s\n", badge, colGap, name, colGap, ch.Summary); err != nil {
			return err
		}
		for _, rem := range ch.Remediation {
			prefix := "->"
			if useColor {
				prefix = "\x1b[2m->\x1b[0m"
			}
			if _, err := fmt.Fprintf(w, "%s%s%s%s%s%s\n", blankBadge, colGap, prefix, arrowPad, colGap, rem); err != nil {
				return err
			}
		}
	}
	return nil
}

func doctorStatusBadge(status doctorStatus, useColor bool) string {
	raw := fmt.Sprintf("[%s]", status)
	if !useColor {
		return raw
	}
	switch status {
	case doctorOK:
		return "\x1b[32m[OK]\x1b[0m"
	case doctorWarn:
		return "\x1b[33m[WARN]\x1b[0m"
	case doctorFail:
		return "\x1b[31m[FAIL]\x1b[0m"
	default:
		return raw
	}
}

func doctorFormatBytes(b int64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case b >= gib:
		if b%gib == 0 {
			return fmt.Sprintf("%d GiB", b/gib)
		}
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(gib))
	case b >= mib:
		if b%mib == 0 {
			return fmt.Sprintf("%d MiB", b/mib)
		}
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		if b%kib == 0 {
			return fmt.Sprintf("%d KiB", b/kib)
		}
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func doctorPlural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
