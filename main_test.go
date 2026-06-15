package main

import "testing"

func TestResolveVersion_PrefersLinkTimeValue(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Fatalf("resolveVersion() = %q, want the link-time value v9.9.9", got)
	}
}

func TestResolveVersion_FallsBackWhenUnset(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	// With no link-time value and no module version under `go test`, the
	// resolver must still return a non-empty marker rather than "".
	version = ""
	if got := resolveVersion(); got == "" {
		t.Fatal("resolveVersion() returned empty string; want a fallback marker")
	}
}
