package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newTestInfoDeps(t *testing.T, backend Backend, now time.Time) (infoDeps, *bytes.Buffer, *[]AuditEvent) {
	t.Helper()
	var buf bytes.Buffer
	var audits []AuditEvent
	deps := infoDeps{
		openBackend: func() (Backend, error) { return backend, nil },
		lockPolicy:  func(ctx context.Context, exclusive bool) (func(), error) { return func() {}, nil },
		appendAudit: func(ev AuditEvent) error {
			audits = append(audits, ev)
			return nil
		},
		now:     func() time.Time { return now },
		stdout:  &buf,
		isTTY:   false,
		noColor: false,
	}
	return deps, &buf, &audits
}

func TestInfo_InvalidSecretName_RejectedBeforeBackend(t *testing.T) {
	opened := false
	deps := infoDeps{
		openBackend: func() (Backend, error) {
			opened = true
			return nil, nil
		},
		stdout: &bytes.Buffer{},
	}

	for _, bad := range []string{"", "meta/foo", "../secret", "has space", strings.Repeat("a", 129)} {
		err := runInfo(context.Background(), bad, false, deps)
		if err == nil {
			t.Errorf("runInfo(%q) succeeded, want invalid secret name error", bad)
		}
		if !strings.Contains(err.Error(), "invalid secret name") {
			t.Errorf("runInfo(%q) error = %q, want invalid secret name", bad, err.Error())
		}
	}
	if opened {
		t.Error("openBackend must not be called when secret name validation fails")
	}
}

func TestInfo_NotFound(t *testing.T) {
	mb := newMemBackend(t)
	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, _, audits := newTestInfoDeps(t, spy, time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))

	err := runInfo(context.Background(), "missing_key", false, deps)
	if err == nil {
		t.Fatal("expected not-found error")
	}
	want := `secret "missing_key" not found; run 'opq list' to see stored secrets`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if len(*audits) != 0 {
		t.Errorf("expected no audit events on not-found, got %+v", *audits)
	}
}

func TestInfo_ActivePolicyFree_NeverReadsValue(t *testing.T) {
	mb := newMemBackend(t)
	mustSet(t, mb, "openai_key", "sk-never-reveal-this-plaintext")
	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	deps, buf, audits := newTestInfoDeps(t, spy, now)

	// Text output
	if err := runInfo(context.Background(), "openai_key", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "sk-never-reveal-this-plaintext") {
		t.Fatal("SECURITY VIOLATION: secret value appeared in info output")
	}
	for _, want := range []string{"Name:", "openai_key", "Backend:", "mem", "Status:", "active", "Created:", "-", "Expires:", "never"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if len(*audits) != 1 || (*audits)[0].Action != ActionList || (*audits)[0].SecretName != "openai_key" {
		t.Errorf("unexpected audit events: %+v", *audits)
	}

	// JSON output
	buf.Reset()
	if err := runInfo(context.Background(), "openai_key", true, deps); err != nil {
		t.Fatalf("runInfo json failed: %v", err)
	}
	if strings.Contains(buf.String(), "sk-never-reveal-this-plaintext") {
		t.Fatal("SECURITY VIOLATION: secret value appeared in info JSON output")
	}
	var got secretInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Name != "openai_key" || got.Backend != "mem" || got.Status != "active" || !got.HasValue {
		t.Errorf("unexpected JSON payload: %+v", got)
	}
	if got.CreatedAt != nil || got.ExpiresAt != nil || got.RevokedAt != nil {
		t.Errorf("expected nil timestamps for policy-free secret, got %+v", got)
	}
}

func TestInfo_ActiveWithExpiry(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	created := now.Add(-2 * time.Hour)
	expires := now.Add(4*time.Hour + 30*time.Minute)

	mustSet(t, mb, "ci_token", "SECRET_CI_TOKEN")
	if err := storeMeta(context.Background(), mb, "ci_token", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: created,
		ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestInfoDeps(t, spy, now)

	if err := runInfo(context.Background(), "ci_token", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"expires 2026-06-14T16:30:00Z",
		"2026-06-14T10:00:00Z (2h ago)",
		"2026-06-14T16:30:00Z (in 4h 30m)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := runInfo(context.Background(), "ci_token", true, deps); err != nil {
		t.Fatalf("runInfo json failed: %v", err)
	}
	var got secretInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "expires 2026-06-14T16:30:00Z" || got.CreatedAt == nil || got.ExpiresAt == nil {
		t.Errorf("unexpected JSON: %+v", got)
	}
	if !got.CreatedAt.Equal(created) || !got.ExpiresAt.Equal(expires) {
		t.Errorf("timestamps mismatch: created=%v expires=%v", got.CreatedAt, got.ExpiresAt)
	}
}

func TestInfo_Expired(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	mustSet(t, mb, "old_token", "OLD_VAL")
	_ = storeMeta(context.Background(), mb, "old_token", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-3 * time.Hour),
	})

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestInfoDeps(t, spy, now)

	if err := runInfo(context.Background(), "old_token", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"EXPIRED", "3h ago", "opq prune"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestInfo_RevokedTombstone(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	revokedAt := now.Add(-45 * time.Minute)
	// Tombstone has only meta/<name>, no value key.
	_ = storeMeta(context.Background(), mb, "burned_key", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-24 * time.Hour),
		RevokedAt: revokedAt,
	})

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestInfoDeps(t, spy, now)

	if err := runInfo(context.Background(), "burned_key", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"REVOKED", "Revoked:", "45m ago", "opq delete burned_key"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := runInfo(context.Background(), "burned_key", true, deps); err != nil {
		t.Fatalf("runInfo json failed: %v", err)
	}
	var got secretInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "REVOKED" || got.HasValue || got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("unexpected revoked JSON: %+v", got)
	}
}

func TestInfo_UpdatePending(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	_ = storeMeta(context.Background(), mb, "half_key", &SecretMeta{
		V:       secretMetaVersion,
		Pending: true,
	})

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestInfoDeps(t, spy, now)

	if err := runInfo(context.Background(), "half_key", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"UPDATE-PENDING", "opq set half_key", "opq delete half_key"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := runInfo(context.Background(), "half_key", true, deps); err != nil {
		t.Fatal(err)
	}
	var got secretInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "UPDATE-PENDING" || !got.Pending {
		t.Errorf("unexpected pending JSON: %+v", got)
	}
}

func TestInfo_MetaError(t *testing.T) {
	mb := newMemBackend(t)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	mustSet(t, mb, "broken_key", "SECRET_BROKEN_VALUE")
	mustSet(t, mb, metaKey("broken_key"), "{bad json")

	spy := &spyNoSecretGetBackend{t: t, inner: mb}
	deps, buf, _ := newTestInfoDeps(t, spy, now)

	if err := runInfo(context.Background(), "broken_key", false, deps); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "SECRET_BROKEN_VALUE") {
		t.Fatal("SECURITY VIOLATION: secret value leaked")
	}
	for _, want := range []string{"meta-error", "opq delete broken_key"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := runInfo(context.Background(), "broken_key", true, deps); err != nil {
		t.Fatal(err)
	}
	var got secretInfo
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "meta-error" || got.MetaError == "" {
		t.Errorf("unexpected meta-error JSON: %+v", got)
	}
}

func TestInfo_ColorAndNoColor(t *testing.T) {
	mb := newMemBackend(t)
	mustSet(t, mb, "k", "v")
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

	deps, buf, _ := newTestInfoDeps(t, mb, now)
	deps.isTTY = true
	deps.noColor = false
	if err := runInfo(context.Background(), "k", false, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[32mactive\x1b[0m") {
		t.Errorf("expected green ANSI status on TTY, got %q", buf.String())
	}

	buf.Reset()
	deps.noColor = true
	if err := runInfo(context.Background(), "k", false, deps); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("NO_COLOR must suppress ANSI escapes, got %q", buf.String())
	}
}

func TestInfo_DefaultDepsDisablesColorOnDumbTerm(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if deps := defaultInfoDeps(); !deps.noColor {
		t.Error("defaultInfoDeps().noColor = false with TERM=dumb, want true")
	}

	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	if deps := defaultInfoDeps(); !deps.noColor {
		t.Error("defaultInfoDeps().noColor = false with NO_COLOR=1, want true")
	}

	t.Setenv("NO_COLOR", "")
	if deps := defaultInfoDeps(); deps.noColor {
		t.Error("defaultInfoDeps().noColor = true with TERM=xterm-256color and unset NO_COLOR, want false")
	}
}

func TestInfo_FormatRelativeAndDuration(t *testing.T) {
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		target time.Time
		want   string
	}{
		{base, "now"},
		{base.Add(500 * time.Millisecond), "in <1s"},
		{base.Add(-500 * time.Millisecond), "<1s ago"},
		{base.Add(45 * time.Second), "in 45s"},
		{base.Add(5 * time.Minute), "in 5m"},
		{base.Add(5*time.Minute + 30*time.Second), "in 5m 30s"},
		{base.Add(-4 * time.Hour), "4h ago"},
		{base.Add(4*time.Hour + 12*time.Minute), "in 4h 12m"},
		{base.Add(3 * 24 * time.Hour), "in 3d"},
		{base.Add(-(3*24*time.Hour + 5*time.Hour)), "3d 5h ago"},
	}
	for _, tc := range cases {
		if got := infoFormatRelative(tc.target, base); got != tc.want {
			t.Errorf("infoFormatRelative(%v, %v) = %q, want %q", tc.target, base, got, tc.want)
		}
	}
}
