//go:build darwin

package main

import (
	"context"
	"os"
)

func (c *MigrateCmd) Run() error {
	ctx := context.Background()
	legacy, err := openLegacyKeychainBackend()
	if err != nil {
		return err
	}
	vault, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	return c.runWith(ctx, legacy, vault, os.Stdout, os.Stderr, defaultMigrateDeps())
}
