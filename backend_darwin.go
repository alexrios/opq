//go:build darwin

package main

import (
	"errors"
	"fmt"

	"github.com/99designs/keyring"
)

// OpenDefaultBackend opens the macOS Keychain backend. Items are stored as
// generic-password items in the user's default (login) keychain, namespaced by
// ServiceName="opq" so List/Get/Delete only ever see opq's own secrets, the
// macOS analogue of the Linux "opq" Secret Service collection.
//
// AllowedBackends is restricted to KeychainBackend so opq never silently falls
// back to the unencrypted file backend. The Keychain backend is compiled only
// under `darwin && cgo` (it links the Security framework via cgo), so a build
// with CGO disabled produces a binary that fails here at run time; the
// ErrNoAvailImpl branch turns that into an actionable message instead of an
// opaque "backend not available".
func OpenDefaultBackend() (Backend, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: []keyring.BackendType{keyring.KeychainBackend},
		// KeychainName is left empty on purpose: use the login keychain, which is
		// unlocked at login and is the parity of the Linux "unlocked Secret
		// Service session". A dedicated keychain would need its own password and
		// unlock lifecycle, friction opq does not want for v1.
		//
		// TrustApplication adds the opq binary to each item's ACL so it can read
		// back secrets it wrote without a password prompt on every call, which is
		// required for `opq exec` and the MCP server to be usable. macOS still
		// prompts once when a rebuilt/moved binary first touches an existing item.
		KeychainTrustApplication: true,
		// Items are readable only while the keychain is unlocked (never when the
		// device is locked); the macOS counterpart of "needs an unlocked session".
		KeychainAccessibleWhenUnlocked: true,
		// Never replicate secrets to iCloud Keychain. Explicit for the reader; the
		// field already defaults to false.
		KeychainSynchronizable: false,
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNoAvailImpl) {
			return nil, fmt.Errorf("macOS Keychain backend unavailable: opq must be built with CGO enabled (CGO_ENABLED=1) and a C toolchain (Xcode Command Line Tools) so it can link the Security framework: %w", err)
		}
		return nil, fmt.Errorf("open keyring: %w", err)
	}
	return &keyringBackend{kr: kr, name: "keychain"}, nil
}
