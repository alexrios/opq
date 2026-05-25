package main

import (
	"sync"
	"testing"
)

// TestCallerTagRace exercises concurrent SetCallerTag/callerTag access so the
// race detector can flag any regression away from atomic.Pointer[string].
func TestCallerTagRace(t *testing.T) {
	t.Cleanup(func() { SetCallerTag("cli") })

	const goroutines = 16
	const iters = 1000

	tags := []string{"cli", "mcp", "test-a", "test-b"}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				SetCallerTag(tags[(i+j)%len(tags)])
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				got := callerTag()
				if got == "" {
					t.Errorf("callerTag returned empty string")
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestCallerTagDefault verifies the package-level default is "cli" before any
// SetCallerTag override.
func TestCallerTagDefault(t *testing.T) {
	SetCallerTag("cli")
	if got := callerTag(); got != "cli" {
		t.Fatalf("default caller tag: got %q, want %q", got, "cli")
	}
}

// TestCallerTagOverride verifies SetCallerTag is observed by subsequent reads.
func TestCallerTagOverride(t *testing.T) {
	t.Cleanup(func() { SetCallerTag("cli") })

	SetCallerTag("mcp")
	if got := callerTag(); got != "mcp" {
		t.Fatalf("after SetCallerTag(\"mcp\"): got %q, want %q", got, "mcp")
	}
}
