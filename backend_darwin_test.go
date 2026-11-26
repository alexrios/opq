//go:build darwin

package main

import "testing"

// TestOpenDefaultBackend_Darwin_KeychainVault checks the darwin backend selects
// the encrypted local vault backed by the macOS Keychain master key and names
// it "keychain-vault". Opening only constructs the backend struct (no Keychain
// or filesystem access), so this never prompts or touches the login keychain;
// round-trip and cross-binary zero-prompt behavior are covered by the
// integration tests.
func TestOpenDefaultBackend_Darwin_KeychainVault(t *testing.T) {
	b, err := OpenDefaultBackend()
	if err != nil {
		t.Fatalf("OpenDefaultBackend: %v", err)
	}
	if b.Name() != "keychain-vault" {
		t.Errorf("Name() = %q, want keychain-vault", b.Name())
	}
}
