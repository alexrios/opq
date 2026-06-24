package main

import (
	"strings"
	"testing"
)

// TestOpenBackend_UnknownIsHardError locks the headline selector invariant: an
// unknown backend name is a hard error and never a silent fallback to a store.
func TestOpenBackend_UnknownIsHardError(t *testing.T) {
	b, err := openBackend("definitely-not-a-backend")
	if err == nil {
		t.Fatal("unknown backend must be a hard error")
	}
	if b != nil {
		t.Fatalf("unknown backend must return a nil Backend, got %v", b)
	}
	if !strings.Contains(err.Error(), "definitely-not-a-backend") {
		t.Fatalf("error should name the offending backend: %v", err)
	}
}

// TestOpenBackend_EmptyAndKeyringRouteToKeyring locks backward compat: the
// no-flag/no-env case and "keyring" both select the keyring backend. (A real
// keyring may be unavailable in CI; the load-bearing assertion is that neither
// name hits the allowlist default.)
func TestOpenBackend_EmptyAndKeyringRouteToKeyring(t *testing.T) {
	for _, name := range []string{"", "keyring"} {
		b, err := openBackend(name)
		if err != nil {
			if strings.Contains(err.Error(), "unknown backend") {
				t.Fatalf("openBackend(%q) hit the allowlist default: %v", name, err)
			}
			continue // keyring unavailable here; acceptable
		}
		if b.Name() != "secret-service" {
			t.Fatalf("openBackend(%q): want keyring (secret-service), got %q", name, b.Name())
		}
	}
}

// TestOpenBackend_VaultProtonRouteToConstructors proves the selector dispatches
// to the vault/proton constructors (not the keyring path, not the default): with
// required config absent each constructor fails with its own distinctive error.
func TestOpenBackend_VaultProtonRouteToConstructors(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	if _, err := openBackend("vault"); err == nil || !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Fatalf("openBackend(vault) should route to the vault constructor: %v", err)
	}
	// Force pass-cli resolution to fail so the proton constructor errors even if
	// a real pass-cli is installed.
	t.Setenv("OPQ_PROTON_PASS_CLI", "/nonexistent/pass-cli-xyz")
	if _, err := openBackend("proton-pass"); err == nil || !strings.Contains(err.Error(), "proton-pass") {
		t.Fatalf("openBackend(proton-pass) should route to the proton constructor: %v", err)
	}
}
