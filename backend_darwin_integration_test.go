//go:build darwin && integration

package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/99designs/keyring"
)

// newTestKeychainBackend builds a keyringBackend over a throwaway keychain file
// in a temp dir, so the test exercises the real macOS Keychain path without
// touching the user's login keychain. The keychain is created non-interactively
// via KeychainPasswordFunc; t.TempDir cleanup removes the file.
//
// This mirrors the production keyringBackend wrapper (same Get/Set/Delete/List
// in backend.go) but with a custom KeychainName so creation/teardown is
// hermetic. Run with: go test -tags integration -run Keychain.
func newTestKeychainBackend(t *testing.T) *keyringBackend {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opq-test")
	kr, err := keyring.Open(keyring.Config{
		ServiceName:                    serviceName,
		AllowedBackends:                []keyring.BackendType{keyring.KeychainBackend},
		KeychainName:                   path, // absolute -> <path>.keychain in the temp dir
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		KeychainPasswordFunc:           func(string) (string, error) { return "opq-test-pw", nil },
	})
	if err != nil {
		t.Fatalf("open test keychain: %v", err)
	}
	return &keyringBackend{kr: kr, name: "keychain-test"}
}

func TestKeychainBackend_RoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newTestKeychainBackend(t)

	// Not found before the first Set.
	if _, err := b.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get before Set: err = %v, want ErrSecretNotFound", err)
	}

	val, err := NewBufferFromBytes([]byte("sk-secret-123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Set(ctx, "api_key", val); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := b.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Bytes()) != "sk-secret-123" {
		t.Errorf("Get returned %q, want sk-secret-123", got.Bytes())
	}
	got.Destroy()

	// Overwrite (AddItem -> ErrorDuplicateItem -> updateItem path).
	val2, err := NewBufferFromBytes([]byte("sk-rotated-456"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Set(ctx, "api_key", val2); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	got2, err := b.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if string(got2.Bytes()) != "sk-rotated-456" {
		t.Errorf("after overwrite Get = %q, want sk-rotated-456", got2.Bytes())
	}
	got2.Destroy()

	keys, err := b.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "api_key" {
		t.Errorf("List = %v, want [api_key]", keys)
	}

	if err := b.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrSecretNotFound", err)
	}
	// Deleting a missing key maps to ErrSecretNotFound.
	if err := b.Delete(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrSecretNotFound", err)
	}
}
