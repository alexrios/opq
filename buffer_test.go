package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuffer_RoundTrip(t *testing.T) {
	src := []byte("sk-test-12345")
	original := append([]byte(nil), src...)

	b := NewBufferFromBytes(src)
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
	b := NewBufferFromBytes(src)
	defer b.Destroy()

	// memguard.Move wipes the source; src must not still hold the secret.
	if bytes.Contains(src, []byte("source-wipe-test")) {
		t.Errorf("source slice was not wiped after NewBufferFromBytes: %q", src)
	}
}

func TestBuffer_DestroyZeroes(t *testing.T) {
	b := NewBufferFromBytes([]byte("destroy-me"))
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
