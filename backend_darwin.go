//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/99designs/keyring"
)

// OpenDefaultBackend opens the macOS vault backend ("keychain-vault").
//
// Secrets and companion "meta/<name>" policy records are stored together in a
// single AES-256-GCM encrypted file (<OS-account-home>/.local/share/opq/vault.enc)
// whose single 256-bit master key lives in the user's default (login) Keychain
// under service "opq-vault" / account "master-key" with an open application ACL.
//
// Why envelope encryption instead of one Keychain item per secret:
//   - Unsigned / ad-hoc-signed CLI binaries (Homebrew releases, go install,
//     local builds) get a new CDHash on every upgrade or rebuild, which breaks
//     per-binary Keychain ACLs across every stored secret and triggers repeated
//     password prompts (the legacy file-based Keychain never uses Touch ID for
//     ACL prompts).
//   - Storing one open-ACL master key in the unlocked login Keychain gives
//     macOS parity with Linux Secret Service (unlocked login session = zero
//     prompts across upgrades), while Seatbelt masks vault.enc from sandboxed
//     AI subprocesses.
//
// The Security framework link requires CGO_ENABLED=1 on darwin; builds without
// CGO fail here with an actionable error instead of degrading to plaintext.
func OpenDefaultBackend() (Backend, error) {
	keys, err := defaultKeychainMasterKeyStore()
	if err != nil {
		return nil, err
	}
	return newVaultBackend("keychain-vault", vaultDir, keys), nil
}

// openLegacyKeychainBackend opens the pre-vault macOS Keychain backend that
// stored each secret directly as a generic-password item under service "opq".
// Used only by `opq migrate` and attribute-only legacy detection (which never
// decrypts data or triggers Keychain password prompts).
func openLegacyKeychainBackend() (Backend, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName:                    serviceName,
		AllowedBackends:                []keyring.BackendType{keyring.KeychainBackend},
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		KeychainSynchronizable:         false,
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNoAvailImpl) {
			return nil, fmt.Errorf("macOS Keychain backend unavailable: opq must be built with CGO enabled (CGO_ENABLED=1) and a C toolchain (Xcode Command Line Tools) so it can link the Security framework: %w", err)
		}
		return nil, fmt.Errorf("open legacy keyring: %w", err)
	}
	return &keyringBackend{kr: kr, name: "keychain-legacy"}, nil
}

// legacyKeychainSecretNames lists secret names present in the legacy macOS
// Keychain store (service="opq") using an attribute-only query that never reads
// secret data or triggers macOS password prompts. Returns visible secret names
// (including names that only exist as meta/<name> tombstones).
func legacyKeychainSecretNames(ctx context.Context) ([]string, error) {
	legacy, err := openLegacyKeychainBackend()
	if err != nil {
		return nil, err
	}
	keys, err := legacy.List(ctx)
	if err != nil {
		return nil, err
	}
	return collectLogicalSecretNames(keys), nil
}

// legacyKeychainHasSecret reports whether name (or its companion meta/<name>)
// exists in the legacy macOS Keychain store. Uses attribute-only listing so it
// never prompts for a password; returns false on any lookup error.
func legacyKeychainHasSecret(ctx context.Context, name string) bool {
	names, err := legacyKeychainSecretNames(ctx)
	if err != nil {
		return false
	}
	return slices.Contains(names, name)
}

// legacyKeychainCount reports how many legacy secrets remain in the macOS
// Keychain store (service="opq"). Attribute-only; never prompts.
func legacyKeychainCount(ctx context.Context) (int, error) {
	names, err := legacyKeychainSecretNames(ctx)
	if err != nil {
		return 0, err
	}
	return len(names), nil
}
