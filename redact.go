package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"sync"
	"sync/atomic"

	"github.com/awnumar/memguard"
)

// RedactingWriter wraps an io.Writer and replaces any registered secret
// value with `[REDACTED:NAME]` before forwarding bytes downstream. It
// preserves a small holdover buffer so secrets split across multiple Write
// calls are still caught.
//
// Concurrency: a single RedactingWriter is safe under one goroutine. Wrap
// stdout and stderr in separate instances and write to each from one
// goroutine, which is the natural pattern with exec.Cmd's pipe wiring.
type RedactingWriter struct {
	mu          sync.Mutex
	w           io.Writer
	secrets     []redactSecret
	maxLen      int
	holdover    []byte
	work        []byte
	out         []byte
	candidates  [256][]redactSecret
	patternRefs *atomic.Int32
	// downTrunc, if set, lets Write short-circuit to pass-through once the
	// downstream starts dropping bytes; otherwise a high-volume producer
	// (`yes`) burns the whole timeout scanning bytes the cap will discard.
	downTrunc   truncatedReporter
	passThrough bool
}

// truncatedReporter is the optional contract a downstream writer implements to
// signal it has begun discarding bytes. Wired by a one-shot assertion in
// NewRedactingWriter. Any interposer between RedactingWriter and the truncating
// sink MUST proxy Truncated() or the short-circuit silently disappears. Today
// only mcp.cappedWriter implements it.
type truncatedReporter interface {
	Truncated() bool
}

type redactSecret struct {
	name  string
	value []byte
}

// hasTruncationShortCircuit reports whether the downstream Truncated()
// short-circuit is wired. Test-only: lets a regression test catch a future
// interposer that fails to proxy Truncated(). Structural check only (downTrunc
// != nil); a behavioral test covers that passThrough actually flips.
func (r *RedactingWriter) hasTruncationShortCircuit() bool {
	return r.downTrunc != nil
}

// NewRedactingWriter copies the given secrets (the caller may destroy the
// sources after) and registers each one's encoded forms too (see
// encodedSecretForms), so an accidental base64/hex emission is still redacted
// to the same NAME.
func NewRedactingWriter(w io.Writer, secrets []NamedSecret) *RedactingWriter {
	rw := &RedactingWriter{w: w, patternRefs: new(atomic.Int32)}
	rw.patternRefs.Store(1)
	if tr, ok := w.(truncatedReporter); ok {
		rw.downTrunc = tr
	}
	for _, s := range secrets {
		for _, form := range encodedSecretForms(s.Value) {
			// Compare bytes directly: map[string] keys would leave immutable secret
			// copies on the garbage-collected heap after Destroy.
			duplicate := false
			for _, prior := range rw.candidates[form[0]] {
				if bytes.Equal(prior.value, form) {
					duplicate = true
					break
				}
			}
			if duplicate {
				memguard.WipeBytes(form)
				continue
			}
			entry := redactSecret{name: s.Name, value: form}
			rw.secrets = append(rw.secrets, entry)
			rw.candidates[form[0]] = append(rw.candidates[form[0]], entry)
			if len(form) > rw.maxLen {
				rw.maxLen = len(form)
			}
		}
	}
	return rw
}

// NewRedactingWriterPair prepares the secret forms once for two independent
// streams. The caller may destroy the source buffers immediately. Each writer
// must be Destroyed; the last Destroy wipes their shared immutable patterns.
func NewRedactingWriterPair(stdout, stderr io.Writer, secrets []NamedSecret) (*RedactingWriter, *RedactingWriter) {
	first := NewRedactingWriter(stdout, secrets)
	first.patternRefs.Add(1)
	second := &RedactingWriter{w: stderr, secrets: first.secrets,
		maxLen: first.maxLen, candidates: first.candidates, patternRefs: first.patternRefs}
	if tr, ok := stderr.(truncatedReporter); ok {
		second.downTrunc = tr
	}
	return first, second
}

// encodingMinRawLen is the floor below which encoded forms are skipped: a short
// secret's hex/base64 (e.g. 4-char hex of 2 bytes) false-positives on innocuous
// output. The raw form is always registered regardless.
const encodingMinRawLen = 4

// encodedSecretForms returns the byte sequences to match for a secret: the raw
// bytes, plus (for secrets >= encodingMinRawLen) base64 std/URL ±padding and hex
// lower/upper, the encodings a tool is likely to emit by accident.
//
// Deliberately NOT covered: URL percent-encoding and JSON escaping (both equal
// the raw for typical alphanumeric keys), arbitrary ciphers (unbounded), and
// entropy heuristics (false-positive prone on real hashes/UUIDs).
func encodedSecretForms(raw []byte) [][]byte {
	if len(raw) == 0 {
		return nil
	}
	// Always include the raw form, even for tiny secrets; the raw match
	// is the load-bearing one. We only suppress the ENCODED expansions
	// below the length floor.
	forms := [][]byte{append([]byte(nil), raw...)}
	if len(raw) < encodingMinRawLen {
		return forms
	}
	// Encode directly to mutable byte slices, so every cached form can be wiped.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		dst := make([]byte, enc.EncodedLen(len(raw)))
		enc.Encode(dst, raw)
		forms = append(forms, dst)
	}
	lower := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(lower, raw)
	upper := append([]byte(nil), lower...)
	for i, c := range upper {
		if c >= 'a' && c <= 'f' {
			upper[i] = c - ('a' - 'A')
		}
	}
	forms = append(forms, lower, upper)
	return forms
}

// NamedSecret pairs a logical name with its value for redactor registration.
// The Value slice is copied internally; the caller retains ownership.
type NamedSecret struct {
	Name  string
	Value []byte
}

func (r *RedactingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.secrets) == 0 {
		// Pass-through. Holdover stays empty.
		return r.w.Write(p)
	}

	// Once the downstream starts dropping bytes, scanning is wasted CPU; flip
	// to pass-through and drop the holdover (those bytes are past the cap too).
	if !r.passThrough && r.downTrunc != nil && r.downTrunc.Truncated() {
		r.passThrough = true
		if len(r.holdover) > 0 {
			for i := range r.holdover {
				r.holdover[i] = 0
			}
			r.holdover = nil
		}
	}
	if r.passThrough {
		return r.w.Write(p)
	}

	// Reuse input/output scratch, wiping the previous backing storage before
	// growing it and the consumed input immediately after scanning.
	r.work = resizeRedactionScratch(r.work, len(r.holdover)+len(p))
	copied := copy(r.work, r.holdover)
	copy(r.work[copied:], p)
	memguard.WipeBytes(r.holdover[:cap(r.holdover)])
	out, hold := r.scan(r.work, false)
	r.holdover = hold
	memguard.WipeBytes(r.work)
	r.out = out
	defer memguard.WipeBytes(r.out[:cap(r.out)])
	if len(out) > 0 {
		if _, err := r.w.Write(out); err != nil {
			// Return len(p): all of p was consumed (some into holdover, some
			// into out). Reporting fewer would invite a retry of bytes we
			// already took; the holdover resumes on the next Write.
			return len(p), err
		}
	}
	return len(p), nil
}

// Flush emits any held-over bytes to the underlying writer. Call this once
// the producer (subprocess) has finished writing, otherwise tail bytes that
// looked like a partial secret prefix will be silently dropped.
func (r *RedactingWriter) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.holdover) == 0 {
		return nil
	}
	out, _ := r.scan(r.holdover, true)
	memguard.WipeBytes(r.holdover[:cap(r.holdover)])
	r.holdover = r.holdover[:0]
	r.out = out
	defer memguard.WipeBytes(r.out[:cap(r.out)])
	if len(out) == 0 {
		return nil
	}
	_, err := r.w.Write(out)
	return err
}

// Destroy zeroes the cached secret values. Call when the redactor is no
// longer needed (subprocess exit).
func (r *RedactingWriter) Destroy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.patternRefs != nil && r.patternRefs.Add(-1) == 0 {
		for i := range r.secrets {
			memguard.WipeBytes(r.secrets[i].value)
			r.secrets[i].value = nil
		}
	}
	r.patternRefs = nil
	r.secrets = nil
	r.candidates = [256][]redactSecret{}
	for _, scratch := range [][]byte{r.holdover, r.work, r.out} {
		memguard.WipeBytes(scratch[:cap(scratch)])
	}
	r.holdover, r.work, r.out = nil, nil, nil
}

// scan walks work byte-by-byte, emitting [REDACTED:NAME] for the longest secret
// matching at each position and suppressing bytes inside an already-matched
// region. A tail that could be a secret prefix is held over for the next Write
// (unless finalize, when no more input is coming).
//
// Two cursors make overlapping secrets work: i tests every position as a
// potential start; emitUpTo tracks how far coverage extends so inner bytes are
// suppressed rather than re-emitted.
func (r *RedactingWriter) scan(work []byte, finalize bool) (out, holdover []byte) {
	out = resizeRedactionScratch(r.out, len(work))[:0]
	emitUpTo := 0 // bytes [0, emitUpTo) are already covered by a redaction token
	i := 0
	for i < len(work) {
		// Find the longest exact match at position i.
		bestLen := 0
		bestName := ""
		for _, s := range r.candidates[work[i]] {
			if len(s.value) <= len(work)-i && bytes.HasPrefix(work[i:], s.value) {
				if len(s.value) > bestLen {
					bestLen = len(s.value)
					bestName = s.name
				}
			}
		}
		if bestLen > 0 {
			out = appendRedactionOutput(out, []byte("[REDACTED:"))
			out = appendRedactionOutput(out, []byte(bestName))
			out = appendRedactionOutput(out, []byte{']'})
			end := i + bestLen
			if end > emitUpTo {
				emitUpTo = end
			}
			i++
			continue
		}
		// No exact match at i.
		if i < emitUpTo {
			// This byte is inside a previously matched region; suppress it.
			i++
			continue
		}
		// Check for a partial-prefix match at i (only meaningful when i is
		// not already covered and the tail is shorter than the longest secret).
		if !finalize && len(work)-i < r.maxLen {
			for _, s := range r.candidates[work[i]] {
				if len(work)-i < len(s.value) && bytes.HasPrefix(s.value, work[i:]) {
					holdover = resizeRedactionScratch(r.holdover, len(work)-i)
					copy(holdover, work[i:])
					return out, holdover
				}
			}
		}
		out = appendRedactionOutput(out, work[i:i+1])
		i++
	}
	return out, r.holdover[:0]
}

// resizeRedactionScratch never abandons a backing array containing plaintext.
func resizeRedactionScratch(buf []byte, size int) []byte {
	if cap(buf) < size {
		memguard.WipeBytes(buf[:cap(buf)])
		return make([]byte, size)
	}
	return buf[:size]
}

func appendRedactionOutput(buf, value []byte) []byte {
	if len(value) > cap(buf)-len(buf) {
		next := make([]byte, len(buf), max(2*cap(buf), len(buf)+len(value)))
		copy(next, buf)
		memguard.WipeBytes(buf[:cap(buf)])
		buf = next
	}
	return append(buf, value...)
}
