package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestPruneCmd_DefaultLeavesRevokedAndPrunesExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	b := newMemBackend(t)

	mustSet(t, b, "active", "v1")
	mustSet(t, b, "expired", "v2")
	if err := storeMeta(ctx, b, "expired", &SecretMeta{V: secretMetaVersion, ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := storeMeta(ctx, b, "revoked", &SecretMeta{V: secretMetaVersion, RevokedAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := (&PruneCmd{}).runWith(ctx, b, &stdout, &stderr, now); err != nil {
		t.Fatalf("runWith: %v", err)
	}
	if !strings.Contains(stdout.String(), "pruned expired\n") {
		t.Errorf("expected expired to be pruned:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "revoked") {
		t.Errorf("default prune must not touch revoked tombstone:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "1 secret(s) pruned") {
		t.Errorf("unexpected stderr summary: %q", stderr.String())
	}
	// Revoked tombstone and active secret survive.
	if m, err := loadMeta(ctx, b, "revoked"); err != nil || !m.IsRevoked() {
		t.Fatalf("revoked tombstone should survive default prune: meta=%+v err=%v", m, err)
	}
	if got, err := b.Get(ctx, "active"); err != nil {
		t.Fatalf("active secret disappeared: %v", err)
	} else {
		got.Destroy()
	}
	if _, err := b.Get(ctx, "expired"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expired secret was not deleted: %v", err)
	}
}

func TestPruneCmd_IncludeRevokedAndDryRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	b := newMemBackend(t)

	mustSet(t, b, "active", "v1")
	mustSet(t, b, "expired", "v2")
	expAt := now.Add(-time.Hour)
	revAt := now.Add(-2 * time.Hour)
	if err := storeMeta(ctx, b, "expired", &SecretMeta{V: secretMetaVersion, ExpiresAt: expAt}); err != nil {
		t.Fatal(err)
	}
	if err := storeMeta(ctx, b, "revoked", &SecretMeta{V: secretMetaVersion, RevokedAt: revAt}); err != nil {
		t.Fatal(err)
	}

	t.Run("--include-revoked --dry-run previews both without deleting", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &PruneCmd{DryRun: true, IncludeRevoked: true}
		if err := cmd.runWith(ctx, b, &stdout, &stderr, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		out := stdout.String()
		if !strings.Contains(out, "would prune expired (expired "+expAt.Format(time.RFC3339)+")") {
			t.Errorf("missing expired dry-run line:\n%s", out)
		}
		if !strings.Contains(out, "would prune revoked (revoked "+revAt.Format(time.RFC3339)+")") {
			t.Errorf("missing revoked dry-run line:\n%s", out)
		}
		if !strings.Contains(stderr.String(), "2 secret(s) would be pruned") {
			t.Errorf("unexpected summary: %q", stderr.String())
		}
		// Nothing deleted on dry-run.
		if m, err := loadMeta(ctx, b, "revoked"); err != nil || !m.IsRevoked() {
			t.Fatalf("dry-run deleted revoked tombstone")
		}
		if got, err := b.Get(ctx, "expired"); err != nil {
			t.Fatalf("dry-run deleted expired secret: %v", err)
		} else {
			got.Destroy()
		}
	})

	t.Run("--include-revoked deletes both expired and revoked tombstones", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &PruneCmd{IncludeRevoked: true}
		if err := cmd.runWith(ctx, b, &stdout, &stderr, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if !strings.Contains(stdout.String(), "pruned expired\n") || !strings.Contains(stdout.String(), "pruned revoked\n") {
			t.Errorf("unexpected stdout:\n%s", stdout.String())
		}
		if !strings.Contains(stderr.String(), "2 secret(s) pruned") {
			t.Errorf("unexpected stderr: %q", stderr.String())
		}
		if m, err := loadMeta(ctx, b, "revoked"); err != nil || m != nil {
			t.Fatalf("revoked tombstone not deleted: meta=%+v err=%v", m, err)
		}
		if _, err := b.Get(ctx, "expired"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("expired secret not deleted: %v", err)
		}
		if got, err := b.Get(ctx, "active"); err != nil {
			t.Fatalf("active secret deleted unexpectedly: %v", err)
		} else {
			got.Destroy()
		}
		// Both deletions audited as ActionPrune.
		lines, err := tailAudit(10)
		if err != nil {
			t.Fatalf("tailAudit: %v", err)
		}
		if len(lines) != 2 {
			t.Fatalf("expected 2 prune audit entries, got %d: %v", len(lines), lines)
		}
	})
}

func TestPruneCmd_ReturnsErrorAfterCompletingFullSweepOnFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	base := newMemBackend(t)
	b := &policyDeleteFaultBackend{memBackend: base, failName: "a_fail_delete"}

	// a_fail_delete: expired, fails during backend.Delete
	mustSet(t, base, "a_fail_delete", "v1")
	if err := storeMeta(ctx, base, "a_fail_delete", &SecretMeta{V: secretMetaVersion, ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// b_corrupt: corrupt metadata causes loadMeta error
	mustSet(t, base, "b_corrupt", "v2")
	mustSet(t, base, metaKey("b_corrupt"), `{corrupt`)
	// z_good_expired: comes AFTER both failures alphabetically; must still be pruned!
	mustSet(t, base, "z_good_expired", "v3")
	if err := storeMeta(ctx, base, "z_good_expired", &SecretMeta{V: secretMetaVersion, ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := (&PruneCmd{}).runWith(ctx, b, &stdout, &stderr, now)
	if err == nil {
		t.Fatal("expected non-zero error when secrets failed to prune")
	}
	if !strings.Contains(err.Error(), "failed to prune 2 secret(s)") {
		t.Errorf("unexpected error message: %v", err)
	}
	// Both failures reported on stderr.
	if !strings.Contains(stderr.String(), "prune a_fail_delete:") || !strings.Contains(stderr.String(), "prune b_corrupt:") {
		t.Errorf("expected per-secret errors on stderr:\n%s", stderr.String())
	}
	// Sweep completed and pruned z_good_expired despite earlier failures.
	if !strings.Contains(stdout.String(), "pruned z_good_expired\n") {
		t.Errorf("sweep aborted before pruning z_good_expired:\n%s", stdout.String())
	}
	if _, gerr := base.Get(ctx, "z_good_expired"); !errors.Is(gerr, ErrSecretNotFound) {
		t.Errorf("z_good_expired should have been pruned: %v", gerr)
	}
}

func TestPruneCmd_KongFlags(t *testing.T) {
	var cli CLI
	p, err := kong.New(&cli)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	if _, err := p.Parse([]string{"prune", "--dry-run", "--include-revoked"}); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !cli.Prune.DryRun || !cli.Prune.IncludeRevoked {
		t.Fatalf("unexpected PruneCmd: %+v", cli.Prune)
	}
}
