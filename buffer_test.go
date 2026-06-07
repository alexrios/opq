package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/awnumar/memguard"
)

func TestBuffer_RoundTrip(t *testing.T) {
	src := []byte("sk-test-12345")
	original := append([]byte(nil), src...)

	b, err := NewBufferFromBytes(src)
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer b.Destroy()

	if !b.IsAlive() {
		t.Fatal("buffer should be alive after construction")
	}
	if b.Size() != len(original) {
		t.Errorf("Size = %d, want %d", b.Size(), len(original))
	}
	if !bytes.Equal(b.Bytes(), original) {
		t.Errorf("Bytes = %q, want %q", b.Bytes(), original)
	}
}

func TestBuffer_SourceWipedAfterMove(t *testing.T) {
	src := []byte("sk-source-wipe-test")
	b, err := NewBufferFromBytes(src)
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer b.Destroy()

	// memguard.Move wipes the source; src must not still hold the secret.
	if bytes.Contains(src, []byte("source-wipe-test")) {
		t.Errorf("source slice was not wiped after NewBufferFromBytes: %q", src)
	}
}

func TestBuffer_DestroyZeroes(t *testing.T) {
	b, err := NewBufferFromBytes([]byte("destroy-me"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	if !b.IsAlive() {
		t.Fatal("expected alive")
	}
	b.Destroy()
	if b.IsAlive() {
		t.Error("expected dead after Destroy")
	}
	if b.Bytes() != nil {
		t.Error("Bytes should be nil after Destroy")
	}
	// Double-destroy is a no-op.
	b.Destroy()
}

func TestBuffer_FromBytesEmpty(t *testing.T) {
	// Stable error text is part of the contract; backend.go wraps this
	// error via fmt.Errorf("keyring get: %w", err) and callers do not
	// errors.Is against a sentinel today, so the text is what propagates
	// to operator-facing logs and audit messages. If this changes, update
	// every grep for "empty secret value" in the codebase.
	const wantMsg = "empty secret value"
	for _, in := range [][]byte{nil, {}} {
		buf, err := NewBufferFromBytes(in)
		if buf != nil {
			t.Errorf("expected nil buffer for empty input, got %v", buf)
		}
		if err == nil {
			t.Errorf("expected error for empty input %v", in)
			continue
		}
		if !strings.Contains(err.Error(), wantMsg) {
			t.Errorf("error %q does not contain %q", err.Error(), wantMsg)
		}
	}
}

func TestBuffer_FromReader(t *testing.T) {
	r := strings.NewReader("hello-from-reader")
	b, err := NewBufferFromReader(r)
	if err != nil {
		t.Fatalf("NewBufferFromReader: %v", err)
	}
	defer b.Destroy()
	if string(b.Bytes()) != "hello-from-reader" {
		t.Errorf("got %q", b.Bytes())
	}
}

func TestBuffer_FromReaderEmpty(t *testing.T) {
	r := strings.NewReader("")
	_, err := NewBufferFromReader(r)
	if err == nil {
		t.Error("expected error for empty value")
	}
}

// TestBuffer_RejectsNULByte locks the joint-review 2026-05 P3
// defense-in-depth check. NUL-bearing values are unusable as env
// vars (Go's os/exec rejects them at start time), so they must be
// rejected at the buffer-constructor boundary rather than silently
// stored and surfaced later as a confusing "exec_start_failed".
// Both constructors share the rule.
func TestBuffer_RejectsNULByte(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"leading_nul", []byte("\x00trailing")},
		{"middle_nul", []byte("sk-abc\x00xyz")},
		{"trailing_nul", []byte("sk-abc\x00")},
		{"only_nul", []byte{0}},
	}
	for _, c := range cases {
		t.Run("FromBytes/"+c.name, func(t *testing.T) {
			src := append([]byte(nil), c.in...)
			buf, err := NewBufferFromBytes(src)
			if buf != nil {
				buf.Destroy()
				t.Fatalf("expected nil buffer for NUL-bearing input, got %v", buf)
			}
			if err == nil || !errors.Is(err, ErrSecretContainsNUL) {
				t.Fatalf("err = %v, want ErrSecretContainsNUL", err)
			}
		})
		t.Run("FromReader/"+c.name, func(t *testing.T) {
			r := bytes.NewReader(c.in)
			buf, err := NewBufferFromReader(r)
			if buf != nil {
				buf.Destroy()
				t.Fatalf("expected nil buffer for NUL-bearing input, got %v", buf)
			}
			if err == nil || !errors.Is(err, ErrSecretContainsNUL) {
				t.Fatalf("err = %v, want ErrSecretContainsNUL", err)
			}
		})
	}
}

// TestWipeBytes_MemguardReplacement locks in the contract used by
// backend.Set: WipeBytes overwrites the buffer in place with zeros.
// If memguard ever changes this semantics, the transient-copy wipe in
// keyringBackend.Set would silently degrade.
func TestWipeBytes_MemguardReplacement(t *testing.T) {
	b := []byte("sk-wipe-me-please")
	memguard.WipeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zero after WipeBytes: %#x (full: %v)", i, v, b)
		}
	}
}
