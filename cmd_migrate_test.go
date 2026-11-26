package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type spyNoGetBackend struct {
	t     *testing.T
	inner Backend
}

func (s *spyNoGetBackend) Name() string { return s.inner.Name() }
func (s *spyNoGetBackend) Get(context.Context, string) (*Buffer, error) {
	s.t.Errorf("SECURITY/UX VIOLATION: dry-run must never call Backend.Get")
	return nil, errors.New("unexpected Get during dry-run")
}
func (s *spyNoGetBackend) Set(ctx context.Context, name string, value *Buffer) error {
	return s.inner.Set(ctx, name, value)
}
func (s *spyNoGetBackend) Delete(ctx context.Context, name string) error {
	return s.inner.Delete(ctx, name)
}
func (s *spyNoGetBackend) List(ctx context.Context) ([]string, error) {
	return s.inner.List(ctx)
}

func TestMigrate_PreservesValuesTTLAndTombstonesAndIsIdempotent(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacy := newMemBackend(t)
	vault, _ := newTestVaultBackend(t, nil)

	// 1. Plain secret
	mustSet(t, legacy, "plain_key", "VAL_PLAIN_SECRET")
	// 2. Expiring secret with TTL metadata
	mustSet(t, legacy, "ttl_key", "VAL_TTL_SECRET")
	expAt := now.Add(48 * time.Hour)
	if err := storeMeta(ctx, legacy, "ttl_key", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-1 * time.Hour),
		ExpiresAt: expAt,
	}); err != nil {
		t.Fatal(err)
	}
	// 3. Revoked tombstone (meta-only, no value)
	revAt := now.Add(-15 * time.Minute)
	if err := storeMeta(ctx, legacy, "revoked_key", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-2 * time.Hour),
		RevokedAt: revAt,
	}); err != nil {
		t.Fatal(err)
	}

	var audited []AuditEvent
	deps := migrateDeps{
		lockPolicy:  func(context.Context, bool) (func(), error) { return func() {}, nil },
		appendAudit: func(ev AuditEvent) error { audited = append(audited, ev); return nil },
	}

	// Dry-run must NOT call Get (zero Keychain prompts) and must NOT modify vault.
	var stdout, stderr bytes.Buffer
	dryCmd := &MigrateCmd{DryRun: true}
	if err := dryCmd.runWith(ctx, &spyNoGetBackend{t: t, inner: legacy}, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "would migrate plain_key (value)") ||
		!strings.Contains(stdout.String(), "would migrate ttl_key (value + policy)") ||
		!strings.Contains(stdout.String(), "would migrate revoked_key (policy/revoked record)") {
		t.Fatalf("unexpected dry-run stdout:\n%s", stdout.String())
	}
	if vKeys, _ := vault.List(ctx); len(vKeys) != 0 {
		t.Fatalf("dry-run modified vault: %v", vKeys)
	}

	// Real migration (default: keeps legacy backup).
	stdout.Reset()
	stderr.Reset()
	cmd := &MigrateCmd{}
	if err := cmd.runWith(ctx, legacy, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("migrate failed: %v\nstderr:\n%s", err, stderr.String())
	}
	combined := stdout.String() + stderr.String()
	for _, secret := range []string{"VAL_PLAIN_SECRET", "VAL_TTL_SECRET"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("SECURITY VIOLATION: secret value %q leaked in migrate output", secret)
		}
	}
	if !strings.Contains(stderr.String(), "migrated 3 secret(s) to keychain-vault (0 skipped)") {
		t.Errorf("unexpected summary:\n%s", stderr.String())
	}
	if len(audited) != 3 {
		t.Errorf("audit event count = %d, want 3", len(audited))
	}
	for _, ev := range audited {
		if ev.Action != ActionMigrate {
			t.Errorf("audit action = %q, want %q", ev.Action, ActionMigrate)
		}
	}

	// Verify plain secret moved intact.
	gotPlain, err := vault.Get(ctx, "plain_key")
	if err != nil {
		t.Fatalf("vault Get plain_key: %v", err)
	}
	if string(gotPlain.Bytes()) != "VAL_PLAIN_SECRET" {
		t.Errorf("plain_key = %q, want VAL_PLAIN_SECRET", gotPlain.Bytes())
	}
	gotPlain.Destroy()

	// Verify TTL secret and metadata preserved intact.
	gotTTL, err := vault.Get(ctx, "ttl_key")
	if err != nil {
		t.Fatalf("vault Get ttl_key: %v", err)
	}
	if string(gotTTL.Bytes()) != "VAL_TTL_SECRET" {
		t.Errorf("ttl_key = %q, want VAL_TTL_SECRET", gotTTL.Bytes())
	}
	gotTTL.Destroy()
	gotTTLMeta, err := loadMeta(ctx, vault, "ttl_key")
	if err != nil || gotTTLMeta == nil || !gotTTLMeta.ExpiresAt.Equal(expAt) {
		t.Fatalf("ttl_key meta = %+v (err=%v), want ExpiresAt=%v", gotTTLMeta, err, expAt)
	}

	// Verify revoked tombstone preserved without creating a value key.
	if _, err := vault.Get(ctx, "revoked_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("revoked_key value err = %v, want ErrSecretNotFound", err)
	}
	gotRevMeta, err := loadMeta(ctx, vault, "revoked_key")
	if err != nil || !gotRevMeta.IsRevoked() || !gotRevMeta.RevokedAt.Equal(revAt) {
		t.Fatalf("revoked_key meta = %+v (err=%v), want RevokedAt=%v", gotRevMeta, err, revAt)
	}

	// Legacy items are still intact as backup.
	if lKeys, _ := legacy.List(ctx); len(lKeys) == 0 {
		t.Fatal("default migrate unexpectedly deleted legacy items")
	}

	// Re-running without --overwrite skips all 3 without calling legacy.Get.
	stdout.Reset()
	stderr.Reset()
	if err := (&MigrateCmd{}).runWith(ctx, &spyNoGetBackend{t: t, inner: legacy}, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("second migrate run failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "migrated 0 secret(s) to keychain-vault (3 skipped)") {
		t.Errorf("unexpected idempotent summary:\n%s", stderr.String())
	}

	// Re-running with --delete-legacy cleans all 3 legacy items without overwriting vault.
	stdout.Reset()
	stderr.Reset()
	if err := (&MigrateCmd{DeleteLegacy: true}).runWith(ctx, legacy, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("cleanup migrate --delete-legacy failed: %v", err)
	}
	if lKeys, _ := legacy.List(ctx); len(lKeys) != 0 {
		t.Fatalf("legacy items remain after --delete-legacy: %v", lKeys)
	}
	if !strings.Contains(stderr.String(), "3 legacy removed") {
		t.Errorf("expected '3 legacy removed' in summary:\n%s", stderr.String())
	}
}

func TestMigrate_OverwriteClearsStaleMetadataAndDeletesLegacy(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacy := newMemBackend(t)
	vault, _ := newTestVaultBackend(t, nil)

	// Vault has an existing entry with TTL metadata; legacy has a plain secret with no metadata.
	mustSet(t, vault, "shared", "OLD_VAULT_VAL")
	if err := storeMeta(ctx, vault, "shared", &SecretMeta{V: secretMetaVersion, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mustSet(t, legacy, "shared", "LEGACY_VAL")

	deps := migrateDeps{
		lockPolicy:  func(context.Context, bool) (func(), error) { return func() {}, nil },
		appendAudit: func(AuditEvent) error { return nil },
	}
	var stdout, stderr bytes.Buffer
	cmd := &MigrateCmd{Overwrite: true, DeleteLegacy: true}
	if err := cmd.runWith(ctx, legacy, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("migrate --overwrite --delete-legacy: %v", err)
	}

	got, err := vault.Get(ctx, "shared")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if string(got.Bytes()) != "LEGACY_VAL" {
		t.Fatalf("shared = %q, want LEGACY_VAL", got.Bytes())
	}
	meta, err := loadMeta(ctx, vault, "shared")
	if err != nil || meta != nil {
		t.Fatalf("stale vault meta survived overwrite: meta=%+v err=%v", meta, err)
	}
	if lKeys, _ := legacy.List(ctx); len(lKeys) != 0 {
		t.Fatalf("legacy item not deleted: %v", lKeys)
	}
}

func TestMigrate_SelectiveNames(t *testing.T) {
	ctx := t.Context()
	legacy := newMemBackend(t)
	vault, _ := newTestVaultBackend(t, nil)

	mustSet(t, legacy, "keep_legacy", "VAL_KEEP")
	mustSet(t, legacy, "move_me", "VAL_MOVE")

	deps := migrateDeps{
		lockPolicy:  func(context.Context, bool) (func(), error) { return func() {}, nil },
		appendAudit: func(AuditEvent) error { return nil },
	}
	var stdout, stderr bytes.Buffer
	cmd := &MigrateCmd{Names: []string{"move_me"}, DeleteLegacy: true}
	if err := cmd.runWith(ctx, legacy, vault, &stdout, &stderr, deps); err != nil {
		t.Fatalf("selective migrate failed: %v", err)
	}

	got, err := vault.Get(ctx, "move_me")
	if err != nil || string(got.Bytes()) != "VAL_MOVE" {
		t.Fatalf("move_me not migrated: err=%v", err)
	}
	got.Destroy()
	if _, err := vault.Get(ctx, "keep_legacy"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("keep_legacy should not have been migrated: err=%v", err)
	}
	if _, err := legacy.Get(ctx, "keep_legacy"); err != nil {
		t.Fatalf("keep_legacy should still be in legacy: %v", err)
	}
	if _, err := legacy.Get(ctx, "move_me"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("move_me should have been removed from legacy: %v", err)
	}

	// Requesting a nonexistent name returns an error.
	stdout.Reset()
	stderr.Reset()
	if err := (&MigrateCmd{Names: []string{"does_not_exist"}}).runWith(ctx, legacy, vault, &stdout, &stderr, deps); err == nil {
		t.Fatal("expected error for missing selective migrate name")
	}
}
