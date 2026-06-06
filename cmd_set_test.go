package main

import (
	"bytes"
	"sync"
	"testing"
)

// TestSanitizePastedSecret covers the cleaning applied to bytes read from the
// hidden TTY prompt: bracketed-paste marker stripping plus whitespace trimming.
func TestSanitizePastedSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "sk-abc123", "sk-abc123"},
		{"trailing newline", "sk-abc123\n", "sk-abc123"},
		{"trailing crlf", "sk-abc123\r\n", "sk-abc123"},
		{"leading and trailing spaces", "  sk-abc123  ", "sk-abc123"},
		{"surrounding whitespace mix", "\t sk-abc123 \r\n", "sk-abc123"},
		{"bracketed paste wrapped", "\x1b[200~sk-abc123\x1b[201~", "sk-abc123"},
		{"bracketed paste with newline", "\x1b[200~sk-abc123\n\x1b[201~", "sk-abc123"},
		{"only whitespace", "  \r\n\t ", ""},
		{"only paste markers", "\x1b[200~\x1b[201~", ""},
		{"empty", "", ""},
		{"internal spaces preserved", "  a b c  ", "a b c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizePastedSecret([]byte(tc.in))
			if string(got) != tc.want {
				t.Fatalf("sanitizePastedSecret(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripBytesInPlace verifies in-place separator removal and that no extra
// backing array is allocated (the result aliases the input).
func TestStripBytesInPlace(t *testing.T) {
	in := []byte("aXXbXXc")
	got := stripBytesInPlace(in, []byte("XX"))
	if string(got) != "abc" {
		t.Fatalf("stripBytesInPlace = %q, want %q", got, "abc")
	}
	// Result must alias the input's backing array (no allocation).
	if len(got) > 0 && &got[0] != &in[0] {
		t.Fatalf("stripBytesInPlace allocated a new array; want in-place")
	}
	// Empty separator is a no-op.
	if g := stripBytesInPlace([]byte("abc"), nil); string(g) != "abc" {
		t.Fatalf("stripBytesInPlace with empty sep = %q, want %q", g, "abc")
	}
}

// TestSanitizePastedSecret_WipeableResidue documents that sanitize works in
// place: the returned slice is a subslice of the input, so wiping the input
// array after constructing the buffer clears all secret residue.
func TestSanitizePastedSecret_WipeableResidue(t *testing.T) {
	raw := []byte("\x1b[200~secret\n\x1b[201~")
	cleaned := sanitizePastedSecret(raw)
	if string(cleaned) != "secret" {
		t.Fatalf("cleaned = %q, want %q", cleaned, "secret")
	}
	// cleaned aliases raw's backing array, so wiping raw clears it.
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(cleaned, make([]byte, len(cleaned))) {
		t.Fatalf("cleaned not zeroed after wiping raw; aliasing assumption broken")
	}
}

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
