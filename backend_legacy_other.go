//go:build !darwin

package main

import "context"

func legacyKeychainCount(context.Context) (int, error) { return 0, nil }
