package main

import (
	"bytes"
	"errors"
	"testing"
)

// flakyWriter fails the first Write call, then forwards subsequent writes
// to an inner buffer. Used to verify RedactingWriter honors io.Writer's
// "n reflects bytes consumed from p" contract when the downstream fails.
type flakyWriter struct {
	failNext bool
	err      error
	buf      bytes.Buffer
}

func (f *flakyWriter) Write(p []byte) (int, error) {
	if f.failNext {
		f.failNext = false
		return 0, f.err
	}
	return f.buf.Write(p)
}

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

func TestRedact_DownstreamErrorReportsFullConsumption(t *testing.T) {
	// When the downstream writer fails, RedactingWriter has already
	// consumed all of p (some bytes into holdover, others redacted into
	// out). It must report n == len(p) along with the error, per the
	// io.Writer contract. A subsequent successful Write should drain the
	// retained holdover plus the new input correctly.
	boom := errors.New("downstream boom")
	fw := &flakyWriter{failNext: true, err: boom}
	rw := NewRedactingWriter(fw, []NamedSecret{{Name: "K", Value: []byte("ABCDEFGH")}})

	input := []byte("hello world ABCD")
	n, err := rw.Write(input)
	if !errors.Is(err, boom) {
		t.Fatalf("want downstream error, got %v", err)
	}
	if n != len(input) {
		t.Errorf("want n=%d (len(p)), got n=%d", len(input), n)
	}
	// Downstream rejected the first write, so nothing was buffered.
	if fw.buf.Len() != 0 {
		t.Errorf("buf should be empty after first failure, got %q", fw.buf.String())
	}

	// Second write completes the split secret. The retained holdover
	// ("ABCD") plus "EFGH" forms the full secret and must be redacted.
	n2, err := rw.Write([]byte("EFGH done"))
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if n2 != len("EFGH done") {
		t.Errorf("second write n=%d", n2)
	}
	if err := rw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// The leading "hello world " was in the first write's `out` and was
	// rejected by the downstream writer; per the io.Writer contract the
	// downstream owns what it accepts/rejects, and RedactingWriter does
	// not buffer non-holdover bytes for retry. The holdover ("ABCD") is
	// intentionally retained, so the split secret still gets redacted.
	if got := fw.buf.String(); got != "[REDACTED:K] done" {
		t.Errorf("got %q", got)
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
