package main

import (
	"bytes"
	"io"
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
	// downTrunc is non-nil iff the downstream writer implements
	// truncatedReporter. Cached at construction to avoid a per-Write type
	// assertion. Once downTrunc.Truncated() returns true, passThrough flips
	// permanently and subsequent Writes bypass scan() entirely (P1-1: CPU
	// DoS short-circuit — without it, a high-volume producer like `yes`
	// burns the full MCP timeout window scanning bytes the cappedWriter
	// downstream silently drops).
	downTrunc   truncatedReporter
	passThrough bool
}

// truncatedReporter is the optional contract a downstream io.Writer can
// implement to signal that it has begun discarding bytes. RedactingWriter
// checks it once per Write and flips to pass-through forever once true.
// Keep this interface single-method and side-effect-free.
//
// NOTE: the wiring is a one-shot type assertion in NewRedactingWriter. Any
// interposer between RedactingWriter and the truncating sink (e.g. a metering
// or logging wrapper) MUST proxy Truncated() — otherwise the P1-1 short-circuit
// silently disappears with no compile-time warning. Today only mcp.cappedWriter
// implements it; review this assumption when adding a new wrapper.
type truncatedReporter interface {
	Truncated() bool
}

type redactSecret struct {
	name  string
	value []byte
}

// hasTruncationShortCircuit reports whether the downstream's Truncated()
// short-circuit is wired (i.e. the constructor's one-shot type assertion
// against truncatedReporter succeeded). Test-only introspection used by
// the P2-6 regression test to lock the P1-1 pipeline invariant — if a
// future refactor inserts an interposer between RedactingWriter and the
// truncating sink that does not proxy Truncated(), this returns false
// and the regression test fails before production damage. Production
// code does not use this; it is intentionally lowercase (package-private)
// so it stays out of the public API surface.
//
// NOTE: this checks structural wiring only (downTrunc != nil). It does
// NOT verify that the downstream's Truncated() actually returns true
// when bytes are dropped — an interposer that proxies the interface but
// always returns false would pass this check. That semantic correctness
// is covered by the companion behavioral test
// TestRunWithSecretsPipeline_ShortCircuitFiresUnderTruncation, which
// asserts that passThrough flips after a real truncation event.
func (r *RedactingWriter) hasTruncationShortCircuit() bool {
	return r.downTrunc != nil
}

// NewRedactingWriter constructs a writer that redacts the given secrets.
// The secrets slice is copied; the caller may destroy the source buffers
// immediately after this returns. Empty secret values are skipped.
func NewRedactingWriter(w io.Writer, secrets []NamedSecret) *RedactingWriter {
	rw := &RedactingWriter{w: w}
	if tr, ok := w.(truncatedReporter); ok {
		rw.downTrunc = tr
	}
	for _, s := range secrets {
		if len(s.Value) == 0 {
			continue
		}
		val := make([]byte, len(s.Value))
		copy(val, s.Value)
		rw.secrets = append(rw.secrets, redactSecret{name: s.Name, value: val})
		if len(val) > rw.maxLen {
			rw.maxLen = len(val)
		}
	}
	return rw
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

	// P1-1: if the downstream has already started dropping bytes (e.g. the
	// MCP cappedWriter past its 256 KiB cap), every further byte scanned is
	// wasted CPU. Flip to pass-through once and drop any retained holdover
	// — those bytes are already past the cap and will be dropped downstream
	// regardless.
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
			// All of p has been consumed: some bytes are now in
			// r.holdover, others were transformed into out and handed
			// to r.w. The io.Writer contract requires n to reflect
			// bytes consumed from p, not bytes accepted downstream;
			// returning 0 here would invite the caller to retry bytes
			// we have already taken. Holdover is intentionally kept
			// so a subsequent successful Write resumes cleanly.
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

// scan walks work byte-by-byte. At each position:
//   - if a registered secret exactly matches starting here, emit
//     "[REDACTED:NAME]" (longest match wins on tie) and mark the matched
//     region as covered; every position inside the region is still tested as
//     a potential secret start so overlapping secrets are also redacted;
//   - else if the byte is inside a previously matched region, suppress it;
//   - else if the remaining suffix could be a prefix of any secret (and we
//     are not in finalize mode), hold it for the next Write;
//   - else emit one byte and advance.
//
// When finalize is true, partial-prefix bytes are emitted verbatim (we know
// no more input is coming).
//
// Overlapping secrets are handled via two cursors:
//   - i advances by 1 each iteration so every byte position is tested as a
//     potential secret start.
//   - emitUpTo tracks the furthest position already covered by a redaction
//     token; bytes below emitUpTo that do not start a new secret are
//     suppressed rather than emitted verbatim.
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
