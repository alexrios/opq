//go:build linux

package main

import (
	"fmt"

	"github.com/99designs/keyring"
)

// OpenDefaultBackend opens the Linux Secret Service backend (libsecret /
// gnome-keyring / KWallet / KeePassXC over D-Bus). AllowedBackends is
// restricted to SecretServiceBackend so opq never silently falls back to an
// unencrypted file backend on a host without a running secret service.
func OpenDefaultBackend() (Backend, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName:             serviceName,
		LibSecretCollectionName: collectionName,
		AllowedBackends:         []keyring.BackendType{keyring.SecretServiceBackend},
	})
	if err != nil {
		return nil, fmt.Errorf("open keyring: %w", err)
	}
	return &keyringBackend{kr: kr, name: "secret-service"}, nil
}
