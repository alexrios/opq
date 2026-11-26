//go:build !darwin

package main

import "context"

func legacyKeychainHasSecret(context.Context, string) bool { return false }

func legacyKeychainCount(context.Context) (int, error) { return 0, nil }
