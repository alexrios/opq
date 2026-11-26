//go:build darwin && !cgo

package main

import "fmt"

func defaultKeychainMasterKeyStore() (masterKeyProvider, error) {
	return nil, fmt.Errorf("macOS Keychain backend unavailable: opq must be built with CGO enabled (CGO_ENABLED=1) and a C toolchain (Xcode Command Line Tools) so it can link the Security framework")
}
