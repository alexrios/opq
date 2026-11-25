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

func TestDeleteCmd_SingleAndMultiple(t *testing.T) {
	ctx := context.Background()

	t.Run("single delete behaves identically", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "only_one", "val")
		var stderr bytes.Buffer
		if err := (&DeleteCmd{Names: []string{"only_one"}}).runWith(ctx, b, &stderr); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if stderr.String() != "deleted \"only_one\"\n" {
			t.Fatalf("stderr = %q, want %q", stderr.String(), "deleted \"only_one\"\n")
		}
		if _, err := b.Get(ctx, "only_one"); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("secret survived delete: %v", err)
		}
	})

	t.Run("multiple deletes including revoked tombstone", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "a", "v1")
		mustSet(t, b, "b", "v2")
		if err := storeMeta(ctx, b, "tomb", &SecretMeta{V: secretMetaVersion, RevokedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		if err := (&DeleteCmd{Names: []string{"a", "b", "tomb"}}).runWith(ctx, b, &stderr); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		for _, n := range []string{"a", "b", "tomb"} {
			if !strings.Contains(stderr.String(), "deleted \""+n+"\"") {
				t.Errorf("missing delete confirmation for %q:\n%s", n, stderr.String())
			}
		}
		keys, _ := b.List(ctx)
		if len(keys) != 0 {
			t.Fatalf("leftover keys after delete: %v", keys)
		}
	})

	t.Run("not-found hint guides operator to opq list", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		err := (&DeleteCmd{Names: []string{"missing"}}).runWith(ctx, b, &stderr)
		if err == nil {
			t.Fatal("expected error for missing secret")
		}
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected ErrSecretNotFound, got %v", err)
		}
		if !strings.Contains(err.Error(), "run 'opq list' to see stored secrets") {
			t.Errorf("missing opq list hint in error: %v", err)
		}
	})

	t.Run("multi-delete finishes remaining items on partial failure and returns error", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "a", "v1")
		mustSet(t, b, "c", "v3")
		var stderr bytes.Buffer
		err := (&DeleteCmd{Names: []string{"a", "missing", "c"}}).runWith(ctx, b, &stderr)
		if err == nil {
			t.Fatal("expected non-zero error when one secret failed")
		}
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected wrapped ErrSecretNotFound, got %v", err)
		}
		// Both existing secrets must still have been deleted.
		if _, gerr := b.Get(ctx, "a"); !errors.Is(gerr, ErrSecretNotFound) {
			t.Errorf("secret a was not deleted: %v", gerr)
		}
		if _, gerr := b.Get(ctx, "c"); !errors.Is(gerr, ErrSecretNotFound) {
			t.Errorf("secret c was not deleted: %v", gerr)
		}
		if !strings.Contains(stderr.String(), "run 'opq list' to see stored secrets") {
			t.Errorf("stderr should contain not-found hint:\n%s", stderr.String())
		}
	})

	t.Run("invalid secret name fails upfront before deleting any secret", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "good", "v1")
		var stderr bytes.Buffer
		err := (&DeleteCmd{Names: []string{"good", "bad/name"}}).runWith(ctx, b, &stderr)
		if err == nil || !strings.Contains(err.Error(), "invalid secret name") {
			t.Fatalf("expected invalid secret name error, got %v", err)
		}
		if got, gerr := b.Get(ctx, "good"); gerr != nil {
			t.Fatalf("good secret should not have been deleted on validation error: %v", gerr)
		} else {
			got.Destroy()
		}
	})
}

func TestDeleteCmd_KongArgs(t *testing.T) {
	var cli CLI
	p, err := kong.New(&cli)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	if _, err := p.Parse([]string{"delete", "a", "b", "c"}); err != nil {
		t.Fatalf("Parse multi-delete failed: %v", err)
	}
	if len(cli.Delete.Names) != 3 || cli.Delete.Names[0] != "a" || cli.Delete.Names[2] != "c" {
		t.Fatalf("unexpected Names: %v", cli.Delete.Names)
	}

	var cli2 CLI
	p2, _ := kong.New(&cli2)
	if _, err := p2.Parse([]string{"delete"}); err == nil {
		t.Fatal("expected error when no secret name is provided")
	}
}
