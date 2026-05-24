package main

import (
	"bytes"
	"testing"
)

func TestRedact_Simple(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("sk-12345")}})
	rw.Write([]byte("token: sk-12345\n"))
	rw.Flush()
	if got := buf.String(); got != "token: [REDACTED:K]\n" {
		t.Errorf("got %q", got)
	}
}

func TestRedact_SplitAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("ABCDEFGH")}})
	rw.Write([]byte("xx ABCD"))
	rw.Write([]byte("EFGH yy"))
	rw.Flush()
	if got := buf.String(); got != "xx [REDACTED:K] yy" {
		t.Errorf("got %q", got)
	}
}

func TestRedact_ByteByByte(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("hello")}})
	for _, b := range []byte("say hello world") {
		rw.Write([]byte{b})
	}
	rw.Flush()
	if got := buf.String(); got != "say [REDACTED:K] world" {
		t.Errorf("got %q", got)
	}
}

func TestRedact_OverlappingLongestWins(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "short", Value: []byte("AB")},
		{Name: "long", Value: []byte("ABCDE")},
	})
	rw.Write([]byte("xx ABCDE yy"))
	rw.Flush()
	if got := buf.String(); got != "xx [REDACTED:long] yy" {
		t.Errorf("got %q", got)
	}
}

func TestRedact_MultipleSecrets(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "A", Value: []byte("foo")},
		{Name: "B", Value: []byte("bar")},
	})
	rw.Write([]byte("foo and bar and foo"))
	rw.Flush()
	if got := buf.String(); got != "[REDACTED:A] and [REDACTED:B] and [REDACTED:A]" {
		t.Errorf("got %q", got)
	}
}

func TestRedact_BinaryPassthrough(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("password")}})
	input := []byte{0x00, 0x01, 0xff, 0xfe, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00}
	rw.Write(input)
	rw.Flush()
	want := []byte{0x00, 0x01, 0xff, 0xfe, '[', 'R', 'E', 'D', 'A', 'C', 'T', 'E', 'D', ':', 'K', ']', 0x00}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("got %q, want %q", buf.Bytes(), want)
	}
}

func TestRedact_NoSecrets(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, nil)
	rw.Write([]byte("no redaction please"))
	rw.Flush()
	if buf.String() != "no redaction please" {
		t.Errorf("got %q", buf.String())
	}
}

func TestRedact_PartialAtEndIsFlushed(t *testing.T) {
	// "AB" is not a complete secret; on Flush it must be emitted verbatim.
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("ABCDEF")}})
	rw.Write([]byte("trailing: AB"))
	if buf.String() != "trailing: " {
		t.Errorf("before flush: got %q", buf.String())
	}
	rw.Flush()
	if buf.String() != "trailing: AB" {
		t.Errorf("after flush: got %q", buf.String())
	}
}

func TestRedact_Destroy(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{{Name: "K", Value: []byte("secret")}})
	rw.Destroy()
	rw.Write([]byte("secret value"))
	rw.Flush()
	// After Destroy the redactor has no secrets, so passthrough.
	if buf.String() != "secret value" {
		t.Errorf("got %q", buf.String())
	}
}
