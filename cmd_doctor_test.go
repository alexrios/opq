package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// spyNoSecretGetBackend wraps a Backend and fails the test immediately if Get
// is ever called on a non-meta key. This enforces the security invariant that
// doctor and info NEVER read plaintext secret values.
type spyNoSecretGetBackend struct {
	t        *testing.T
	inner    Backend
	listErr  error
	getCalls []string
}

func (s *spyNoSecretGetBackend) Name() string { return s.inner.Name() }

func (s *spyNoSecretGetBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	s.getCalls = append(s.getCalls, name)
	if !isMetaKey(name) {
		s.t.Errorf("SECURITY VIOLATION: Backend.Get called on non-meta key %q", name)
		return nil, errors.New("forbidden value read in test spy")
	}
	return s.inner.Get(ctx, name)
}

func (s *spyNoSecretGetBackend) Set(ctx context.Context, name string, value *Buffer) error {
	return s.inner.Set(ctx, name, value)
}

func (s *spyNoSecretGetBackend) Delete(ctx context.Context, name string) error {
	return s.inner.Delete(ctx, name)
}

func (s *spyNoSecretGetBackend) List(ctx context.Context) ([]string, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.inner.List(ctx)
}

func newTestDoctorDeps(t *testing.T, backend Backend) (doctorDeps, *bytes.Buffer, string) {
	t.Helper()
	root := t.TempDir()
	var buf bytes.Buffer
	deps := doctorDeps{
		version:         func() string { return "v1.3.0-test" },
		goos:            "darwin",
		goarch:          "arm64",
		openBackend:     func() (Backend, error) { return backend, nil },
		verifySandbox:   func() error { return nil },
		auditLogPath:    func() (string, error) { return filepath.Join(root, "state", "opq", "audit.log"), nil },
		policyLockDir:   func() (string, error) { return filepath.Join(root, "state", "opq-policy"), nil },
		rotateThreshold: 10 * 1024 * 1024,
		now:             func() time.Time { return time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC) },
		stdout:          &buf,
		isTTY:           false,
		noColor:         false,
	}
	return deps, &buf, root
}

func findDoctorCheck(t *testing.T, report doctorReport, name string) doctorCheck {
	t.Helper()
	for _, ch := range report.Checks {
		if ch.Name == name {
			return ch
		}
	}
	t.Fatalf("doctor check %q not found in report: %+v", name, report.Checks)
	return doctorCheck{}
}

func TestDoctor_AllHealthy_FreshInstallReadOnly(t *testing.T) {
	mb := newMemBackend(t)
	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, root := newTestDoctorDeps(t, spy)

	// Text mode
	if err := runDoctor(context.Background(), false, deps); err != nil {
		t.Fatalf("runDoctor text returned unexpected error: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"[OK]",
		"binary",
		"opq v1.3.0-test (darwin/arm64)",
		"keyring",
		"mem (0 secrets)",
		"sandbox",
		"Seatbelt (sandbox-exec) available",
		"audit_log",
		"(not created yet)",
		"policy_lock",
		"secret_metadata",
		"no secrets stored",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("non-TTY output must not contain ANSI escapes:\n%q", out)
	}

	// Verify doctor was strictly read-only: neither state dir nor audit.log was created.
	if _, err := os.Lstat(filepath.Join(root, "state")); !os.IsNotExist(err) {
		t.Errorf("doctor must not create state directories on a fresh install, stat err = %v", err)
	}

	// JSON mode
	buf.Reset()
	if err := runDoctor(context.Background(), true, deps); err != nil {
		t.Fatalf("runDoctor json returned unexpected error: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if !report.Healthy {
		t.Errorf("report.Healthy = false, want true")
	}
	if report.Version != "v1.3.0-test" || report.OS != "darwin" || report.Arch != "arm64" {
		t.Errorf("unexpected report metadata: %+v", report)
	}
	for _, name := range []string{"binary", "keyring", "sandbox", "audit_log", "policy_lock", "secret_metadata"} {
		ch := findDoctorCheck(t, report, name)
		if ch.Status != doctorOK {
			t.Errorf("check %s status = %s, want OK (summary=%q)", name, ch.Status, ch.Summary)
		}
	}
}

func TestDoctor_ExistingStateHealthyAndNeverReadsValues(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

	mustSet(t, mb, "plain_secret", "SUPER_SECRET_PLAIN_VALUE")
	mustSet(t, mb, "expiring_secret", "SUPER_SECRET_EXPIRING_VALUE")
	if err := storeMeta(context.Background(), mb, "expiring_secret", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, root := newTestDoctorDeps(t, spy)
	deps.now = func() time.Time { return now }

	// Pre-create properly secured audit dir/log/lock and policy dir/lock.
	auditDir := filepath.Join(root, "state", "opq")
	policyDir := filepath.Join(root, "state", "opq-policy")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "audit.log"), []byte(`{"action":"list"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, auditLockFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runDoctor(context.Background(), false, deps); err != nil {
		t.Fatalf("runDoctor failed: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, forbidden := range []string{"SUPER_SECRET_PLAIN_VALUE", "SUPER_SECRET_EXPIRING_VALUE"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("SECURITY VIOLATION: secret value leaked into doctor output")
		}
	}
	if !strings.Contains(out, "mem (2 secrets)") {
		t.Errorf("expected 2 secrets in output:\n%s", out)
	}
	if !strings.Contains(out, "mode 0600") {
		t.Errorf("expected audit log mode 0600 in output:\n%s", out)
	}
	if !strings.Contains(out, "2 active secrets, all metadata healthy") {
		t.Errorf("expected healthy metadata summary:\n%s", out)
	}
}

func TestDoctor_KeyringFailure_OSSpecificRemediation(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		openErr  error
		wantHint string
	}{
		{
			name:     "darwin CGO unavailable",
			goos:     "darwin",
			openErr:  errors.New("macOS Keychain backend unavailable: CGO_ENABLED=1 required"),
			wantHint: "CGO_ENABLED=1",
		},
		{
			name:     "darwin locked keychain",
			goos:     "darwin",
			openErr:  errors.New("open keyring: user interaction not allowed"),
			wantHint: "security unlock-keychain",
		},
		{
			name:     "linux secret service",
			goos:     "linux",
			openErr:  errors.New("open keyring: dbus session bus unavailable"),
			wantHint: "DBUS_SESSION_BUS_ADDRESS",
		},
		{
			name:     "unsupported OS",
			goos:     "windows",
			openErr:  errors.New("no secrets backend available"),
			wantHint: "Linux Secret Service and macOS Keychain only",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps, buf, _ := newTestDoctorDeps(t, nil)
			deps.goos = tc.goos
			deps.openBackend = func() (Backend, error) { return nil, tc.openErr }

			err := runDoctor(context.Background(), true, deps)
			if err == nil {
				t.Fatal("expected error when keyring fails")
			}

			var report doctorReport
			if jerr := json.Unmarshal(buf.Bytes(), &report); jerr != nil {
				t.Fatalf("invalid JSON: %v\n%s", jerr, buf.String())
			}
			if report.Healthy {
				t.Error("report.Healthy = true, want false")
			}
			kr := findDoctorCheck(t, report, "keyring")
			if kr.Status != doctorFail {
				t.Errorf("keyring status = %s, want FAIL", kr.Status)
			}
			joined := strings.Join(kr.Remediation, "\n")
			if !strings.Contains(joined, tc.wantHint) {
				t.Errorf("remediation %q missing %q", joined, tc.wantHint)
			}
			meta := findDoctorCheck(t, report, "secret_metadata")
			if meta.Status != doctorWarn || !strings.Contains(meta.Summary, "skipped") {
				t.Errorf("expected secret_metadata skipped WARN when keyring fails, got %+v", meta)
			}
		})
	}
}

func TestDoctor_KeyringListFailure(t *testing.T) {
	mb := newMemBackend(t)
	spy := &spyNoSecretGetBackend{t: t, inner: mb, listErr: errors.New("collection locked")}
	deps, buf, _ := newTestDoctorDeps(t, spy)
	deps.goos = "linux"

	if err := runDoctor(context.Background(), true, deps); err == nil {
		t.Fatal("expected error when backend.List fails")
	}
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	kr := findDoctorCheck(t, report, "keyring")
	if kr.Status != doctorFail || !strings.Contains(kr.Summary, "listing keys failed") {
		t.Errorf("unexpected keyring check: %+v", kr)
	}
}

func TestDoctor_SandboxFailure(t *testing.T) {
	mb := newMemBackend(t)
	deps, buf, _ := newTestDoctorDeps(t, mb)
	deps.goos = "linux"
	deps.verifySandbox = func() error {
		return errors.New("bubblewrap (bwrap) not found in PATH: apt install bubblewrap")
	}

	if err := runDoctor(context.Background(), true, deps); err == nil {
		t.Fatal("expected error when sandbox fails")
	}
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	sbx := findDoctorCheck(t, report, "sandbox")
	if sbx.Status != doctorFail {
		t.Errorf("sandbox status = %s, want FAIL", sbx.Status)
	}
	if !strings.Contains(sbx.Summary, "bubblewrap (bwrap)") {
		t.Errorf("sandbox summary = %q, want bubblewrap label", sbx.Summary)
	}
	if len(sbx.Remediation) == 0 || !strings.Contains(sbx.Remediation[0], "apt install bubblewrap") {
		t.Errorf("sandbox remediation missing install hint: %+v", sbx.Remediation)
	}
}

func TestDoctor_AuditDirAndFileFailures(t *testing.T) {
	t.Run("symlink audit dir", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		target := filepath.Join(root, "real-target")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "link-opq")
		if err := os.Symlink(target, linkDir); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return filepath.Join(linkDir, "audit.log"), nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on symlink audit dir")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "symlink") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
	})

	t.Run("audit dir loose permissions", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return filepath.Join(dir, "audit.log"), nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on 0755 audit dir")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "0755") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
		if !strings.Contains(strings.Join(ch.Remediation, " "), "chmod 700") {
			t.Errorf("expected chmod 700 remediation, got %+v", ch.Remediation)
		}
	})

	t.Run("audit log loose permissions", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "audit.log")
		if err := os.WriteFile(logPath, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(logPath, 0o644); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return logPath, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on 0644 audit.log")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "0644") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
		if !strings.Contains(strings.Join(ch.Remediation, " "), "chmod 600") {
			t.Errorf("expected chmod 600 remediation, got %+v", ch.Remediation)
		}
	})

	t.Run("symlink audit log", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		realFile := filepath.Join(root, "other.log")
		if err := os.WriteFile(realFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "audit.log")
		if err := os.Symlink(realFile, logPath); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return logPath, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on symlink audit.log")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "symlink") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
	})

	t.Run("audit log at rotation threshold warns and exits 0", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		deps.rotateThreshold = 100
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "audit.log")
		if err := os.WriteFile(logPath, bytes.Repeat([]byte("a"), 120), 0o600); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return logPath, nil }

		if err := runDoctor(context.Background(), true, deps); err != nil {
			t.Fatalf("rotation threshold warning must exit 0, got: %v", err)
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if !report.Healthy {
			t.Error("report.Healthy = false on WARN-only report, want true")
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorWarn || !strings.Contains(ch.Summary, "rotate") {
			t.Errorf("expected WARN with rotation notice, got %+v", ch)
		}
	})

	t.Run("audit log exceeding read cap fails", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "audit.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(auditReadCap + 1024); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
		deps.auditLogPath = func() (string, error) { return logPath, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error when audit.log exceeds auditReadCap")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "read cap") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
	})

	t.Run("uncreatable audit dir ancestor", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		blocker := filepath.Join(root, "file-not-dir")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return filepath.Join(blocker, "opq", "audit.log"), nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error when ancestor is a file")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail {
			t.Errorf("expected FAIL, got %+v", ch)
		}
	})

	t.Run("dangling symlink audit ancestor fails", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dangling := filepath.Join(root, "dangling-state")
		if err := os.Symlink(filepath.Join(root, "does-not-exist"), dangling); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return filepath.Join(dangling, "opq", "audit.log"), nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error when audit ancestor is a dangling symlink")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "dangling symlink") {
			t.Errorf("expected FAIL with dangling symlink, got %+v", ch)
		}
	})

	t.Run("symlink audit lock fails", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "other.lock")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, auditLockFileName)); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return filepath.Join(dir, "audit.log"), nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on symlink audit.lock")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "symlink") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
	})

	t.Run("rotated audit log loose permissions fails", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		dir := filepath.Join(root, "opq")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "audit.log")
		if err := os.WriteFile(logPath+".1", []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(logPath+".1", 0o644); err != nil {
			t.Fatal(err)
		}
		deps.auditLogPath = func() (string, error) { return logPath, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on 0644 audit.log.1")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "audit_log")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "0644") {
			t.Errorf("unexpected audit_log check: %+v", ch)
		}
	})
}

func TestDoctor_PolicyLockFailures(t *testing.T) {
	t.Run("symlink policy dir", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		target := filepath.Join(root, "real-policy")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "link-policy")
		if err := os.Symlink(target, linkDir); err != nil {
			t.Fatal(err)
		}
		deps.policyLockDir = func() (string, error) { return linkDir, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on symlink policy dir")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "policy_lock")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "symlink") {
			t.Errorf("unexpected policy_lock check: %+v", ch)
		}
	})

	t.Run("loose policy lock file mode", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		pDir := filepath.Join(root, "opq-policy")
		if err := os.MkdirAll(pDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(pDir, 0o700); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(pDir, "policy.lock")
		if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockPath, 0o644); err != nil {
			t.Fatal(err)
		}
		deps.policyLockDir = func() (string, error) { return pDir, nil }

		if err := runDoctor(context.Background(), true, deps); err == nil {
			t.Fatal("expected error on 0644 policy.lock")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		ch := findDoctorCheck(t, report, "policy_lock")
		if ch.Status != doctorFail || !strings.Contains(ch.Summary, "0644") {
			t.Errorf("unexpected policy_lock check: %+v", ch)
		}
	})
}

func TestDoctor_MetadataWarningsAndRecoveryCommands_ExitZero(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// 1 active
	mustSet(t, mb, "ok_key", "VAL_OK")
	// 2 expired
	mustSet(t, mb, "exp_1", "VAL_EXP1")
	_ = storeMeta(ctx, mb, "exp_1", &SecretMeta{V: secretMetaVersion, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour)})
	mustSet(t, mb, "exp_2", "VAL_EXP2")
	_ = storeMeta(ctx, mb, "exp_2", &SecretMeta{V: secretMetaVersion, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now}) // inclusive boundary
	// 1 update-pending
	_ = storeMeta(ctx, mb, "pending_key", &SecretMeta{V: secretMetaVersion, Pending: true})
	// 1 meta-error (corrupt JSON)
	mustSet(t, mb, "corrupt_key", "VAL_CORRUPT")
	mustSet(t, mb, metaKey("corrupt_key"), "{not-valid-json")
	// 1 revoked tombstone (no value)
	_ = storeMeta(ctx, mb, "revoked_key", &SecretMeta{V: secretMetaVersion, RevokedAt: now.Add(-30 * time.Minute)})

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestDoctorDeps(t, spy)
	deps.now = func() time.Time { return now }

	// WARN-only report MUST exit 0 (nil error).
	if err := runDoctor(ctx, false, deps); err != nil {
		t.Fatalf("WARN-only doctor should return nil, got: %v", err)
	}
	textOut := buf.String()
	for _, want := range []string{
		"[WARN]",
		"1 UPDATE-PENDING",
		"1 meta-error",
		"2 EXPIRED",
		"1 REVOKED",
		"opq set <name>",
		"opq delete <name>",
		"opq prune",
	} {
		if !strings.Contains(textOut, want) {
			t.Errorf("text output missing %q:\n%s", want, textOut)
		}
	}
	for _, forbidden := range []string{"VAL_OK", "VAL_EXP1", "VAL_EXP2", "VAL_CORRUPT"} {
		if strings.Contains(textOut, forbidden) {
			t.Fatalf("SECURITY VIOLATION: secret value %q leaked in doctor output", forbidden)
		}
	}

	// Verify JSON counts too.
	buf.Reset()
	if err := runDoctor(ctx, true, deps); err != nil {
		t.Fatalf("WARN-only doctor json should return nil, got: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !report.Healthy {
		t.Errorf("report.Healthy = false on WARN-only report, want true")
	}
	mc := findDoctorCheck(t, report, "secret_metadata")
	if mc.Status != doctorWarn {
		t.Errorf("secret_metadata status = %s, want WARN", mc.Status)
	}
	rawDetails, _ := json.Marshal(mc.Details)
	var counts doctorMetaCounts
	if err := json.Unmarshal(rawDetails, &counts); err != nil {
		t.Fatalf("decode metadata counts: %v", err)
	}
	wantCounts := doctorMetaCounts{
		Total:         6,
		Active:        1,
		Expiring:      0,
		Expired:       2,
		Revoked:       1,
		UpdatePending: 1,
		MetaError:     1,
	}
	if counts != wantCounts {
		t.Errorf("counts = %+v, want %+v", counts, wantCounts)
	}
}

func TestDoctor_RevokedOnlyIsOKWithRecoveryHint(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	mustSet(t, mb, "live_key", "LIVE")
	_ = storeMeta(context.Background(), mb, "burned_key", &SecretMeta{V: secretMetaVersion, RevokedAt: now.Add(-10 * time.Minute)})

	deps, buf, _ := newTestDoctorDeps(t, mb)
	deps.now = func() time.Time { return now }

	if err := runDoctor(context.Background(), true, deps); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	mc := findDoctorCheck(t, report, "secret_metadata")
	if mc.Status != doctorOK {
		t.Errorf("revoked-only metadata status = %s, want OK", mc.Status)
	}
	if !strings.Contains(mc.Summary, "1 REVOKED") {
		t.Errorf("summary %q should mention 1 REVOKED", mc.Summary)
	}
	if !strings.Contains(strings.Join(mc.Remediation, " "), "opq delete <name>") {
		t.Errorf("expected delete recovery hint for revoked tombstone: %+v", mc.Remediation)
	}
}

func TestDoctor_ColorRespectsTTYAndNoColor(t *testing.T) {
	mb := newMemBackend(t)

	deps, buf, _ := newTestDoctorDeps(t, mb)
	deps.isTTY = true
	deps.noColor = false
	if err := runDoctor(context.Background(), false, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[32m[OK]\x1b[0m") {
		t.Errorf("TTY with color enabled should emit ANSI green [OK], got:\n%q", buf.String())
	}

	buf.Reset()
	deps.noColor = true
	if err := runDoctor(context.Background(), false, deps); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("NO_COLOR=1 must suppress ANSI escapes, got:\n%q", buf.String())
	}
}

func TestDoctor_ColorTTYPreservesExactColumnAlignment(t *testing.T) {
	ansiSGRRe := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	mustSet(t, mb, "exp_key", "VAL_EXP")
	_ = storeMeta(ctx, mb, "exp_key", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
	})
	_ = storeMeta(ctx, mb, "pending_key", &SecretMeta{
		V:       secretMetaVersion,
		Pending: true,
	})

	deps, colorBuf, _ := newTestDoctorDeps(t, mb)
	deps.now = func() time.Time { return now }
	deps.isTTY = true
	deps.noColor = false
	if err := runDoctor(ctx, false, deps); err != nil {
		t.Fatalf("color runDoctor failed: %v", err)
	}
	colorOut := colorBuf.String()
	if !strings.Contains(colorOut, "\x1b[32m[OK]\x1b[0m") ||
		!strings.Contains(colorOut, "\x1b[33m[WARN]\x1b[0m") ||
		!strings.Contains(colorOut, "\x1b[2m->\x1b[0m") {
		t.Fatalf("expected ANSI styled [OK], [WARN], and -> in color output:\n%q", colorOut)
	}

	var plainBuf bytes.Buffer
	deps.stdout = &plainBuf
	deps.isTTY = false
	if err := runDoctor(ctx, false, deps); err != nil {
		t.Fatalf("plain runDoctor failed: %v", err)
	}
	plainOut := plainBuf.String()

	stripped := ansiSGRRe.ReplaceAllString(colorOut, "")
	if stripped != plainOut {
		t.Fatalf("stripped color output drifted from plain output:\n--- stripped ---\n%s\n--- plain ---\n%s", stripped, plainOut)
	}

	// Explicitly check that column 1 (check names and '->') and column 2
	// (summaries and remediation text) start at identical visible offsets.
	lines := strings.Split(strings.TrimRight(stripped, "\n"), "\n")
	var binaryCol, metaCol, arrowCol, summaryCol, remCol int
	binaryCol, metaCol, arrowCol, summaryCol, remCol = -1, -1, -1, -1, -1
	for _, line := range lines {
		if idx := strings.Index(line, "binary"); idx >= 0 {
			binaryCol = idx
			summaryCol = strings.Index(line, "opq v1.3.0-test")
		}
		if idx := strings.Index(line, "secret_metadata"); idx >= 0 {
			metaCol = idx
		}
		if idx := strings.Index(line, "->"); idx >= 0 && arrowCol == -1 {
			arrowCol = idx
			remCol = strings.Index(line, "1 UPDATE-PENDING:")
		}
	}
	if binaryCol < 0 || metaCol != binaryCol || arrowCol != binaryCol {
		t.Errorf("column 1 misaligned: binary=%d secret_metadata=%d arrow=%d\n%s", binaryCol, metaCol, arrowCol, stripped)
	}
	if summaryCol < 0 || remCol != summaryCol {
		t.Errorf("column 2 misaligned: summary=%d remediation=%d\n%s", summaryCol, remCol, stripped)
	}
}

func TestDoctor_DefaultDepsDisablesColorOnDumbTerm(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if deps := defaultDoctorDeps(); !deps.noColor {
		t.Error("defaultDoctorDeps().noColor = false with TERM=dumb, want true")
	}

	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	if deps := defaultDoctorDeps(); !deps.noColor {
		t.Error("defaultDoctorDeps().noColor = false with NO_COLOR=1, want true")
	}

	t.Setenv("NO_COLOR", "")
	if deps := defaultDoctorDeps(); deps.noColor {
		t.Error("defaultDoctorDeps().noColor = true with TERM=xterm-256color and unset NO_COLOR, want false")
	}
}

func TestDoctor_VaultAndLegacyMigrationChecks(t *testing.T) {
	t.Run("fresh vault is OK and read-only", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		vDir := filepath.Join(root, "share", "opq")
		deps.vaultDir = func() (string, error) { return vDir, nil }
		deps.legacyCount = func(context.Context) (int, error) { return 0, nil }

		if err := runDoctor(t.Context(), true, deps); err != nil {
			t.Fatalf("runDoctor failed: %v", err)
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		vc := findDoctorCheck(t, report, "vault")
		if vc.Status != doctorOK || !strings.Contains(vc.Summary, "(not created yet)") {
			t.Errorf("unexpected fresh vault check: %+v", vc)
		}
		if _, err := os.Lstat(vDir); !os.IsNotExist(err) {
			t.Errorf("doctor must not create vault dir, stat err = %v", err)
		}
	})

	t.Run("legacy Keychain secrets trigger WARN with opq migrate remediation", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		deps.vaultDir = func() (string, error) { return filepath.Join(root, "share", "opq"), nil }
		deps.legacyCount = func(context.Context) (int, error) { return 4, nil }

		if err := runDoctor(t.Context(), true, deps); err != nil {
			t.Fatalf("WARN-only doctor must exit 0, got: %v", err)
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if !report.Healthy {
			t.Error("report.Healthy = false on WARN-only report, want true")
		}
		kr := findDoctorCheck(t, report, "keyring")
		if kr.Status != doctorWarn || !strings.Contains(kr.Summary, "4 legacy Keychain secrets pending migration") {
			t.Errorf("unexpected keyring check: %+v", kr)
		}
		if !strings.Contains(strings.Join(kr.Remediation, "\n"), "opq migrate") {
			t.Errorf("expected 'opq migrate' remediation, got %+v", kr.Remediation)
		}
	})

	t.Run("loose vault.enc permissions fail", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		vDir := filepath.Join(root, "share", "opq")
		if err := os.MkdirAll(vDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(vDir, 0o700); err != nil {
			t.Fatal(err)
		}
		vPath := filepath.Join(vDir, vaultFileName)
		if err := os.WriteFile(vPath, []byte("enc"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(vPath, 0o644); err != nil {
			t.Fatal(err)
		}
		deps.vaultDir = func() (string, error) { return vDir, nil }

		if err := runDoctor(t.Context(), true, deps); err == nil {
			t.Fatal("expected error on 0644 vault.enc")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		vc := findDoctorCheck(t, report, "vault")
		if vc.Status != doctorFail || !strings.Contains(vc.Summary, "0644") {
			t.Errorf("unexpected vault check: %+v", vc)
		}
	})

	t.Run("symlink vault dir fails", func(t *testing.T) {
		mb := newMemBackend(t)
		deps, buf, root := newTestDoctorDeps(t, mb)
		realDir := filepath.Join(root, "real-vault")
		if err := os.MkdirAll(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "link-vault")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		deps.vaultDir = func() (string, error) { return linkDir, nil }

		if err := runDoctor(t.Context(), true, deps); err == nil {
			t.Fatal("expected error on symlink vault dir")
		}
		var report doctorReport
		if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		vc := findDoctorCheck(t, report, "vault")
		if vc.Status != doctorFail || !strings.Contains(vc.Summary, "symlink") {
			t.Errorf("unexpected vault check: %+v", vc)
		}
	})
}
