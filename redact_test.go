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

// TestRedact_OverlappingSecretsAtSamePosition verifies the H3 fix: when two
// registered secrets overlap (S2 starts inside S1's matched region), both are
// redacted. Input "ABCD" with secrets {ABC, BCD}: ABC matches at offset 0 and
// BCD matches at offset 1. The output must contain both redaction tokens; the
// plain bytes C and D must not appear because they are covered by BCD.
func TestRedact_OverlappingSecretsAtSamePosition(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "S1", Value: []byte("ABC")},
		{Name: "S2", Value: []byte("BCD")},
	})
	rw.Write([]byte("ABCD"))
	rw.Flush()
	got := buf.String()
	// Both overlapping secrets must be redacted.
	if !bytes.Contains([]byte(got), []byte("[REDACTED:S1]")) {
		t.Errorf("S1 not redacted; got %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("[REDACTED:S2]")) {
		t.Errorf("S2 not redacted; got %q", got)
	}
	// No raw secret bytes may survive: none of A, B, C, D appear as a lone
	// verbatim sequence outside a redaction token.
	if got != "[REDACTED:S1][REDACTED:S2]" {
		t.Errorf("unexpected output %q; want \"[REDACTED:S1][REDACTED:S2]\"", got)
	}
}

// TestRedact_SecretSelfOverlap verifies that a self-overlapping secret (one
// that overlaps with a copy of itself) is handled correctly. Secret "ABA",
// input "ABABA": matches start at offset 0 (ABA covers 0-2) and offset 2
// (ABA covers 2-4). Both must be redacted.
func TestRedact_SecretSelfOverlap(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "K", Value: []byte("ABA")},
	})
	rw.Write([]byte("ABABA"))
	rw.Flush()
	got := buf.String()
	if got != "[REDACTED:K][REDACTED:K]" {
		t.Errorf("got %q; want \"[REDACTED:K][REDACTED:K]\"", got)
	}
}

// TestRedact_OverlapAcrossSplitWrites verifies that overlapping secrets are
// still both redacted when the input arrives as two separate Write calls that
// straddle the boundary. Write("AB") then Write("CD") with secrets {ABC,BCD}.
func TestRedact_OverlapAcrossSplitWrites(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "S1", Value: []byte("ABC")},
		{Name: "S2", Value: []byte("BCD")},
	})
	rw.Write([]byte("AB"))
	rw.Write([]byte("CD"))
	rw.Flush()
	got := buf.String()
	if got != "[REDACTED:S1][REDACTED:S2]" {
		t.Errorf("got %q; want \"[REDACTED:S1][REDACTED:S2]\"", got)
	}
}

// TestRedact_NoFalsePositives verifies that substrings of registered secrets
// that do not form a complete secret are not redacted.
func TestRedact_NoFalsePositives(t *testing.T) {
	var buf bytes.Buffer
	rw := NewRedactingWriter(&buf, []NamedSecret{
		{Name: "K", Value: []byte("ABCDE")},
	})
	rw.Write([]byte("AB XYZ ABCD"))
	rw.Flush()
	got := buf.String()
	if got != "AB XYZ ABCD" {
		t.Errorf("got %q; want unmodified input", got)
	}
}

// truncatingWriter mirrors mcp.cappedWriter's contract: it forwards bytes
// to an inner buffer up to `cap`, then silently drops further bytes and
// reports truncated=true. Used to exercise the RedactingWriter P1-1
// short-circuit without pulling in the MCP package.
type truncatingWriter struct {
	inner     bytes.Buffer
	remaining int
	truncated bool
}

func (t *truncatingWriter) Write(p []byte) (int, error) {
	if t.remaining <= 0 {
		t.truncated = true
		return len(p), nil
	}
	if len(p) <= t.remaining {
		n, err := t.inner.Write(p)
		t.remaining -= n
		return n, err
	}
	take := p[:t.remaining]
	n, err := t.inner.Write(take)
	t.remaining -= n
	t.truncated = true
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func (t *truncatingWriter) Truncated() bool { return t.truncated }

// plainWriter has no Truncated() method — used to confirm RedactingWriter
// still redacts normally when the downstream does not implement the
// optional truncatedReporter interface.
type plainWriter struct{ bytes.Buffer }

// TestRedact_NoTruncatedReporter_UnchangedBehavior confirms that when the
// downstream writer does not implement truncatedReporter, RedactingWriter
// behaves exactly as before: secrets are redacted, holdover works.
func TestRedact_NoTruncatedReporter_UnchangedBehavior(t *testing.T) {
	pw := &plainWriter{}
	rw := NewRedactingWriter(pw, []NamedSecret{{Name: "K", Value: []byte("sk-12345")}})
	if rw.downTrunc != nil {
		t.Fatalf("downTrunc should be nil when downstream lacks Truncated()")
	}
	rw.Write([]byte("hello sk-12345 world"))
	rw.Flush()
	if got := pw.String(); got != "hello [REDACTED:K] world" {
		t.Errorf("got %q", got)
	}
}

// TestRedact_ShortCircuitOnTruncation verifies P1-1: once the downstream
// reports Truncated(), the redactor flips to pass-through and bytes that
// would otherwise be redacted are forwarded verbatim. This is observable
// because the truncatingWriter's inner buffer ALSO drops post-cap bytes,
// so we test by setting the cap larger than the first batch but writing
// the secret in the second batch after manually flipping truncated=true.
func TestRedact_ShortCircuitOnTruncation(t *testing.T) {
	tw := &truncatingWriter{remaining: 1 << 20} // generous cap; we'll flip manually
	rw := NewRedactingWriter(tw, []NamedSecret{{Name: "K", Value: []byte("sekret")}})
	if rw.downTrunc == nil {
		t.Fatalf("downTrunc should be set when downstream implements Truncated()")
	}

	// Pre-flip: secret is redacted normally.
	if _, err := rw.Write([]byte("before sekret\n")); err != nil {
		t.Fatalf("pre-flip write: %v", err)
	}
	if !bytes.Contains(tw.inner.Bytes(), []byte("[REDACTED:K]")) {
		t.Fatalf("pre-flip: expected redaction, got %q", tw.inner.String())
	}

	// Flip the downstream signal and write a fresh secret. The redactor
	// must pass the bytes through verbatim, proving scan() was bypassed.
	tw.truncated = true
	preLen := tw.inner.Len()
	if _, err := rw.Write([]byte("after sekret\n")); err != nil {
		t.Fatalf("post-flip write: %v", err)
	}
	post := tw.inner.Bytes()[preLen:]
	if !bytes.Contains(post, []byte("sekret")) {
		t.Errorf("post-flip: expected raw passthrough (cap not yet hit), got %q", post)
	}
	if bytes.Contains(post, []byte("[REDACTED:K]")) {
		t.Errorf("post-flip: redaction still applied, scan() was not bypassed: %q", post)
	}

	// Subsequent writes must remain in pass-through without re-checking
	// (sanity: even if we cleared truncated, passThrough is sticky).
	tw.truncated = false
	preLen = tw.inner.Len()
	if _, err := rw.Write([]byte("still sekret\n")); err != nil {
		t.Fatalf("third write: %v", err)
	}
	post = tw.inner.Bytes()[preLen:]
	if bytes.Contains(post, []byte("[REDACTED:K]")) {
		t.Errorf("passthrough should be sticky; got %q", post)
	}
}

// TestRedact_HoldoverDiscardedOnTruncation verifies that any holdover bytes
// retained before the truncation flip are discarded (not retained, not
// flushed downstream). The previous Write left "AB" in holdover as a
// possible prefix of "ABCDEFGH"; after truncation, that holdover must be
// dropped, and a subsequent Flush must not emit it.
func TestRedact_HoldoverDiscardedOnTruncation(t *testing.T) {
	tw := &truncatingWriter{remaining: 1 << 20}
	rw := NewRedactingWriter(tw, []NamedSecret{{Name: "K", Value: []byte("ABCDEFGH")}})

	// First write leaves "AB" in holdover (partial prefix of the secret).
	if _, err := rw.Write([]byte("xx AB")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if len(rw.holdover) == 0 {
		t.Fatalf("expected non-empty holdover, got none")
	}

	// Flip and write — the holdover must be dropped, not flushed.
	tw.truncated = true
	preLen := tw.inner.Len()
	if _, err := rw.Write([]byte(" tail")); err != nil {
		t.Fatalf("post-flip write: %v", err)
	}
	if len(rw.holdover) != 0 {
		t.Errorf("holdover should be cleared after truncation flip, got %q", rw.holdover)
	}
	post := tw.inner.Bytes()[preLen:]
	// The "AB" that was in holdover must NOT reappear; only " tail" passes.
	if bytes.Contains(post, []byte("AB")) {
		t.Errorf("holdover bytes leaked downstream: %q", post)
	}
	if string(post) != " tail" {
		t.Errorf("got %q, want %q", post, " tail")
	}

	// Flush must be a no-op (holdover already cleared).
	if err := rw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
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
