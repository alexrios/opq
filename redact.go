package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"sync"
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
	mu       sync.Mutex
	w        io.Writer
	secrets  []redactSecret
	maxLen   int
	holdover []byte
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
	rw := &RedactingWriter{w: w}
	if tr, ok := w.(truncatedReporter); ok {
		rw.downTrunc = tr
	}
	// De-dup: a secret's encoded forms can coincide; one entry suffices.
	seen := make(map[string]bool)
	for _, s := range secrets {
		for _, form := range encodedSecretForms(s.Value) {
			if seen[string(form)] {
				continue
			}
			seen[string(form)] = true
			val := make([]byte, len(form))
			copy(val, form)
			rw.secrets = append(rw.secrets, redactSecret{name: s.Name, value: val})
			if len(val) > rw.maxLen {
				rw.maxLen = len(val)
			}
		}
	}
	return rw
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
	// base64: both alphabets, padded and unpadded. EncodeToString gives
	// the padded form; trimming trailing '=' yields the raw form, which
	// is also what RawStdEncoding / RawURLEncoding emit directly.
	stdPadded := base64.StdEncoding.EncodeToString(raw)
	urlPadded := base64.URLEncoding.EncodeToString(raw)
	stdRaw := base64.RawStdEncoding.EncodeToString(raw)
	urlRaw := base64.RawURLEncoding.EncodeToString(raw)
	// hex: lower (Go default) and upper (Java/some hexdumps).
	hexLower := hex.EncodeToString(raw)
	hexUpper := strings.ToUpper(hexLower)
	for _, s := range []string{stdPadded, stdRaw, urlPadded, urlRaw, hexLower, hexUpper} {
		forms = append(forms, []byte(s))
	}
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

	// Build the working buffer: holdover + p.
	work := make([]byte, 0, len(r.holdover)+len(p))
	work = append(work, r.holdover...)
	work = append(work, p...)

	out, hold := r.scan(work, false)
	r.holdover = hold
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
	r.holdover = nil
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
	for i := range r.secrets {
		for j := range r.secrets[i].value {
			r.secrets[i].value[j] = 0
		}
		r.secrets[i].value = nil
	}
	r.secrets = nil
	for i := range r.holdover {
		r.holdover[i] = 0
	}
	r.holdover = nil
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
	out = make([]byte, 0, len(work))
	emitUpTo := 0 // bytes [0, emitUpTo) are already covered by a redaction token
	i := 0
	for i < len(work) {
		// Find the longest exact match at position i.
		bestLen := 0
		bestName := ""
		for _, s := range r.secrets {
			if len(s.value) <= len(work)-i && bytes.HasPrefix(work[i:], s.value) {
				if len(s.value) > bestLen {
					bestLen = len(s.value)
					bestName = s.name
				}
			}
		}
		if bestLen > 0 {
			out = append(out, "[REDACTED:"...)
			out = append(out, bestName...)
			out = append(out, ']')
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
			for _, s := range r.secrets {
				if len(work)-i < len(s.value) && bytes.HasPrefix(s.value, work[i:]) {
					holdover = append(holdover, work[i:]...)
					return out, holdover
				}
			}
		}
		out = append(out, work[i])
		i++
	}
	return out, nil
}
