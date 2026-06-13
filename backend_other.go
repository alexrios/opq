//go:build !linux && !darwin

package main

import "fmt"

// OpenDefaultBackend reports that no secrets backend exists for this OS. opq
// stores secrets in the OS-native store, implemented for Linux (Secret Service)
// and macOS (Keychain) only.
func OpenDefaultBackend() (Backend, error) {
	return nil, fmt.Errorf("no secrets backend available for this OS (Linux Secret Service or macOS Keychain only)")
}
