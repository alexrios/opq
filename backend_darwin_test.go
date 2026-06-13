//go:build darwin

package main

import "testing"

// TestOpenDefaultBackend_Darwin_Keychain checks the darwin backend selects the
// Keychain and names it "keychain". keyring.Open only constructs the backend
// struct (no keychain access), so this never prompts or touches the login
// keychain; the round-trip behavior is covered by the integration test.
func TestOpenDefaultBackend_Darwin_Keychain(t *testing.T) {
	b, err := OpenDefaultBackend()
	if err != nil {
		t.Fatalf("OpenDefaultBackend: %v", err)
	}
	if b.Name() != "keychain" {
		t.Errorf("Name() = %q, want keychain", b.Name())
	}
}
