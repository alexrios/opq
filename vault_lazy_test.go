package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingBackend struct {
	inner Backend
	gets  atomic.Int32
}

func (c *countingBackend) Name() string { return c.inner.Name() }
func (c *countingBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	c.gets.Add(1)
	return c.inner.Get(ctx, name)
}
func (c *countingBackend) Set(ctx context.Context, name string, value *Buffer) error {
	return c.inner.Set(ctx, name, value)
}
func (c *countingBackend) Delete(ctx context.Context, name string) error {
	return c.inner.Delete(ctx, name)
}
func (c *countingBackend) List(ctx context.Context) ([]string, error) {
	return c.inner.List(ctx)
}

func withTempPolicyAndAuditHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	origHome := policyHomeDir
	policyHomeDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { policyHomeDir = origHome })
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	return root
}

func TestLazyMigration_ReadOnlyCommandsNeverCallLegacyGet(t *testing.T) {
	withTempPolicyAndAuditHome(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacyRaw := newMemBackend(t)
	mustSet(t, legacyRaw, "legacy_plain", "LEGACY_SECRET_1")
	mustSet(t, legacyRaw, "legacy_ttl", "LEGACY_SECRET_2")
	mustSet(t, legacyRaw, metaKey("legacy_ttl"), `{"v":2,"expires_at":"2030-01-01T00:00:00Z"}`)
	// Revoked tombstone in legacy (meta-only, no value)
	mustSet(t, legacyRaw, metaKey("legacy_revoked"), `{"v":2,"revoked_at":"2026-11-01T00:00:00Z"}`)
	// Stale legacy key whose vault counterpart is already REVOKED -> vault must win
	mustSet(t, legacyRaw, "shadowed_revoked", "STALE_LEGACY_VAL")

	vb, _ := newTestVaultBackend(t, nil)
	mustSet(t, vb, "vault_active", "VAULT_SECRET_1")
	if err := storeMeta(ctx, vb, "shadowed_revoked", &SecretMeta{V: secretMetaVersion, RevokedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Attach spy that FAILS THE TEST if legacy.Get is ever invoked.
	vb.legacy = &spyNoGetBackend{t: t, inner: legacyRaw}

	// 1. opq list (non-TTY, TTY, --long, --json, --status legacy) -> 0 legacy.Get calls
	var out, errBuf bytes.Buffer
	if err := (&ListCmd{Status: "all"}).runWith(ctx, vb, &out, &errBuf, false, now); err != nil {
		t.Fatalf("list non-TTY failed: %v", err)
	}
	listText := out.String()
	for _, want := range []string{"vault_active", "legacy_plain\tlegacy", "legacy_ttl\tlegacy", "shadowed_revoked\tREVOKED"} {
		if !strings.Contains(listText, want) {
			t.Errorf("list non-TTY missing %q:\n%s", want, listText)
		}
	}
	for _, forbidden := range []string{"LEGACY_SECRET_1", "LEGACY_SECRET_2", "STALE_LEGACY_VAL", "VAULT_SECRET_1"} {
		if strings.Contains(listText, forbidden) {
			t.Fatalf("SECURITY VIOLATION: secret %q leaked in list output", forbidden)
		}
	}

	out.Reset()
	if err := (&ListCmd{Status: "legacy", JSON: true}).runWith(ctx, vb, &out, &errBuf, false, now); err != nil {
		t.Fatalf("list --status legacy --json failed: %v", err)
	}
	var jsonRows []listJSONEntry
	if err := json.Unmarshal(out.Bytes(), &jsonRows); err != nil {
		t.Fatalf("decode list json: %v", err)
	}
	gotLegacyNames := make([]string, 0, len(jsonRows))
	for _, r := range jsonRows {
		if r.Status != "legacy" {
			t.Errorf("expected status=legacy for %s, got %q", r.Name, r.Status)
		}
		gotLegacyNames = append(gotLegacyNames, r.Name)
	}
	if !slices.Equal(gotLegacyNames, []string{"legacy_plain", "legacy_revoked", "legacy_ttl"}) {
		t.Errorf("--status legacy names = %v, want [legacy_plain legacy_revoked legacy_ttl]", gotLegacyNames)
	}

	// 2. MCP list_secrets merge logic -> hides legacy_revoked AND shadowed_revoked!
	vaultKeys, err := vb.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacyKeys, err := vb.ListLegacyKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mcpVisible := filterVisibleSecretNames(mergeKeysWithLegacy(vaultKeys, legacyKeys))
	wantMCP := []string{"legacy_plain", "legacy_ttl", "vault_active"}
	if !slices.Equal(mcpVisible, wantMCP) {
		t.Errorf("MCP visible names = %v, want %v (must hide both legacy and vault revoked tombstones)", mcpVisible, wantMCP)
	}

	// 3. opq info on legacy secret -> 0 legacy.Get calls
	out.Reset()
	infoD := infoDeps{
		openBackend: func() (Backend, error) { return vb, nil },
		lockPolicy:  func(context.Context, bool) (func(), error) { return func() {}, nil },
		appendAudit: func(AuditEvent) error { return nil },
		now:         func() time.Time { return now },
		stdout:      &out,
	}
	if err := runInfo(ctx, "legacy_plain", false, infoD); err != nil {
		t.Fatalf("info on legacy secret failed: %v", err)
	}
	if !strings.Contains(out.String(), "keychain-legacy") || !strings.Contains(out.String(), "auto-migrates on first use") {
		t.Errorf("unexpected info output for legacy secret:\n%s", out.String())
	}

	// 4. opq set --no-clobber and --keep-ttl against legacy secret -> refuse without legacy.Get
	errBuf.Reset()
	err = (&SetCmd{Name: "legacy_plain", NoClobber: true}).runWith(
		ctx, vb, strings.NewReader("newval"), false, &errBuf, false, nil, func() time.Time { return now },
	)
	if err == nil || !strings.Contains(err.Error(), "legacy macOS Keychain") {
		t.Fatalf("set --no-clobber on legacy secret = %v, want refusal", err)
	}
	errBuf.Reset()
	err = (&SetCmd{Name: "legacy_ttl", KeepTTL: true}).runWith(
		ctx, vb, strings.NewReader("newval"), false, &errBuf, false, nil, func() time.Time { return now },
	)
	if err == nil || !strings.Contains(err.Error(), "opq migrate legacy_ttl") {
		t.Fatalf("set --keep-ttl on legacy secret = %v, want migration hint", err)
	}

	// 5. opq prune -> never touches legacy.Get
	out.Reset()
	errBuf.Reset()
	if err := (&PruneCmd{}).runWith(ctx, vb, &out, &errBuf, now); err != nil {
		t.Fatalf("prune failed: %v", err)
	}
}

func TestLazyMigration_ResolveMigratesOnceAndEnforcesPolicy(t *testing.T) {
	withTempPolicyAndAuditHome(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacy := newMemBackend(t)
	// Plain secret
	mustSet(t, legacy, "plain_key", "PLAIN_VAL")
	// Active TTL secret
	mustSet(t, legacy, "valid_ttl", "TTL_VAL")
	expFuture := now.Add(24 * time.Hour)
	if err := storeMeta(ctx, legacy, "valid_ttl", &SecretMeta{V: secretMetaVersion, CreatedAt: now.Add(-time.Hour), ExpiresAt: expFuture}); err != nil {
		t.Fatal(err)
	}
	// Expired TTL secret
	mustSet(t, legacy, "expired_ttl", "EXPIRED_VAL")
	if err := storeMeta(ctx, legacy, "expired_ttl", &SecretMeta{V: secretMetaVersion, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Revoked tombstone (meta-only)
	if err := storeMeta(ctx, legacy, "revoked_key", &SecretMeta{V: secretMetaVersion, RevokedAt: now.Add(-10 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	counter := &countingBackend{inner: legacy}
	vb, _ := newTestVaultBackend(t, nil)
	vb.legacy = counter

	// 1. Plain secret migrates on first resolve and deletes legacy copy.
	buf, err := resolveSecret(ctx, vb, "plain_key", now)
	if err != nil {
		t.Fatalf("resolve plain_key: %v", err)
	}
	if string(buf.Bytes()) != "PLAIN_VAL" {
		t.Fatalf("plain_key = %q, want PLAIN_VAL", buf.Bytes())
	}
	buf.Destroy()
	if _, err := legacy.Get(ctx, "plain_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("legacy plain_key should have been deleted after lazy migration, err = %v", err)
	}

	// Second resolve must NOT touch legacy at all.
	getsBefore := counter.gets.Load()
	buf2, err := resolveSecret(ctx, vb, "plain_key", now)
	if err != nil || string(buf2.Bytes()) != "PLAIN_VAL" {
		t.Fatalf("second resolve plain_key: err=%v", err)
	}
	buf2.Destroy()
	if counter.gets.Load() != getsBefore {
		t.Errorf("second resolve called legacy.Get (%d -> %d)", getsBefore, counter.gets.Load())
	}

	// 2. Valid TTL secret migrates value + metadata and returns value.
	bufTTL, err := resolveSecret(ctx, vb, "valid_ttl", now)
	if err != nil || string(bufTTL.Bytes()) != "TTL_VAL" {
		t.Fatalf("resolve valid_ttl: err=%v", err)
	}
	bufTTL.Destroy()
	migratedMeta, err := loadMeta(ctx, vb, "valid_ttl")
	if err != nil || migratedMeta == nil || !migratedMeta.ExpiresAt.Equal(expFuture) {
		t.Fatalf("valid_ttl metadata not preserved: %+v err=%v", migratedMeta, err)
	}

	// 3. Expired secret migrates into vault AND is immediately refused as ErrSecretExpired.
	if got, err := resolveSecret(ctx, vb, "expired_ttl", now); !errors.Is(err, ErrSecretExpired) {
		if got != nil {
			got.Destroy()
		}
		t.Fatalf("resolve expired_ttl = %v, want ErrSecretExpired", err)
	}
	// Second resolve refuses directly from vault without touching legacy.
	getsBefore = counter.gets.Load()
	if _, err := resolveSecret(ctx, vb, "expired_ttl", now); !errors.Is(err, ErrSecretExpired) {
		t.Fatalf("second resolve expired_ttl = %v, want ErrSecretExpired", err)
	}
	if counter.gets.Load() != getsBefore {
		t.Errorf("second resolve of expired secret touched legacy.Get")
	}

	// 4. Revoked tombstone migrates into vault AND is refused as ErrSecretRevoked.
	if _, err := resolveSecret(ctx, vb, "revoked_key", now); !errors.Is(err, ErrSecretRevoked) {
		t.Fatalf("resolve revoked_key = %v, want ErrSecretRevoked", err)
	}
	if lKeys, _ := legacy.List(ctx); len(lKeys) != 0 {
		t.Errorf("expected all lazily resolved legacy keys cleaned up, remaining: %v", lKeys)
	}
}

func TestLazyMigration_ConcurrentResolvesMigrateOnce(t *testing.T) {
	withTempPolicyAndAuditHome(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacy := newMemBackend(t)
	mustSet(t, legacy, "shared_key", "CONCURRENT_VAL")
	counter := &countingBackend{inner: legacy}

	vb, _ := newTestVaultBackend(t, nil)
	vb.legacy = counter

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			buf, err := resolveSecret(ctx, vb, "shared_key", now)
			if err != nil {
				errs <- err
				return
			}
			defer buf.Destroy()
			if string(buf.Bytes()) != "CONCURRENT_VAL" {
				errs <- errors.New("unexpected value")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent resolve failed: %v", err)
	}
	if got := counter.gets.Load(); got != 1 {
		t.Errorf("legacy.Get called %d times under concurrency, want 1", got)
	}
}

func TestLazyMigration_DeleteRevokeAndSetPreventResurrection(t *testing.T) {
	withTempPolicyAndAuditHome(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	legacy := newMemBackend(t)
	mustSet(t, legacy, "del_legacy_only", "VAL_DEL_ONLY")
	mustSet(t, legacy, "del_both", "VAL_OLD_LEGACY")
	mustSet(t, legacy, "rev_legacy_only", "VAL_REV_ONLY")
	mustSet(t, legacy, "set_overwrite", "VAL_OLD_SET")

	vb, _ := newTestVaultBackend(t, nil)
	mustSet(t, vb, "del_both", "VAL_IN_VAULT")
	// Use spyNoGetBackend so delete/revoke/set MUST succeed without ever calling legacy.Get!
	vb.legacy = &spyNoGetBackend{t: t, inner: legacy}

	// 1. Delete legacy-only secret -> succeeds without legacy.Get and stays gone.
	if err := deleteSecret(ctx, vb, "del_legacy_only"); err != nil {
		t.Fatalf("deleteSecret legacy-only: %v", err)
	}
	if _, err := resolveSecret(ctx, vb, "del_legacy_only", now); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("resolve after delete legacy-only = %v, want ErrSecretNotFound", err)
	}

	// 2. Delete secret present in both vault and legacy -> cannot resurrect.
	if err := deleteSecret(ctx, vb, "del_both"); err != nil {
		t.Fatalf("deleteSecret both: %v", err)
	}
	if _, err := resolveSecret(ctx, vb, "del_both", now); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("deleted secret resurrected from legacy: err = %v", err)
	}

	// 3. Revoke legacy-only secret -> wipes legacy value without legacy.Get & writes tombstone.
	if err := revokeSecret(ctx, vb, "rev_legacy_only", now); err != nil {
		t.Fatalf("revokeSecret legacy-only: %v", err)
	}
	if _, err := legacy.Get(ctx, "rev_legacy_only"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("legacy value survived revoke: err = %v", err)
	}
	if _, err := resolveSecret(ctx, vb, "rev_legacy_only", now); !errors.Is(err, ErrSecretRevoked) {
		t.Fatalf("resolve revoked legacy secret = %v, want ErrSecretRevoked", err)
	}

	// 4. storeSecret overwrites legacy secret -> cleans legacy copy so later delete won't resurrect old value.
	newVal, err := NewBufferFromBytes([]byte("VAL_NEW_SET"))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeSecret(ctx, vb, "set_overwrite", newVal, nil); err != nil {
		t.Fatalf("storeSecret overwrite legacy: %v", err)
	}
	newVal.Destroy()
	if _, err := legacy.Get(ctx, "set_overwrite"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("stale legacy copy survived storeSecret: err = %v", err)
	}
	if err := deleteSecret(ctx, vb, "set_overwrite"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSecret(ctx, vb, "set_overwrite", now); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("old legacy value resurrected after set+delete: err = %v", err)
	}
}
