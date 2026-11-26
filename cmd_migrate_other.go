//go:build !darwin

package main

import (
	"fmt"
	"os"
)

func (c *MigrateCmd) Run() error {
	fmt.Fprintln(os.Stderr, "opq migrate is only needed on macOS (migrating legacy per-item Keychain entries to the encrypted local vault); nothing to do on this platform")
	return nil
}
