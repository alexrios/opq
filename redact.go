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
//
// Each registered secret is expanded into multiple byte sequences so the
// redactor catches common encodings of the same value (base64 std, base64
// URL, raw-no-pad variants of both, lower-hex, upper-hex). This closes
// gap #2 (encoding bypass) for the headline encodings — a subprocess that
// accidentally emits its API key in any of these forms still produces
// `[REDACTED:NAME]` instead of the encoded plaintext. Encoded forms map
// to the same NAME as the raw secret; from the caller's view there is one
// secret with multiple wire representations. See encodedSecretForms for
// the full expansion list and rationale.
func NewRedactingWriter(w io.Writer, secrets []NamedSecret) *RedactingWriter {
	rw := &RedactingWriter{w: w}
	if tr, ok := w.(truncatedReporter); ok {
		rw.downTrunc = tr
	}
	// De-dup: short / low-entropy secrets can produce encoded forms that
	// collide with the raw value (e.g. raw "abc" lower-hex "616263" cannot
	// collide, but a base64 form of a tiny secret could coincidentally
	// equal another encoded form). The map-of-string key is fine here —
	// we copy out into fresh []byte for each survivor before stashing.
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

// encodingMinRawLen is the minimum raw-secret byte length below which we
// skip registering encoded forms. Short secrets (< 4 bytes) produce
// encoded forms short enough to false-positive on innocuous subprocess
// output (a 2-byte secret has a 4-char hex form like "ab12" that could
// trivially appear in random text). The raw form is still registered.
// 4 bytes is a deliberately conservative floor — any secret short enough
// to fall below it is unlikely to be a real-world credential and the loss
// of encoded-form coverage is acceptable.
const encodingMinRawLen = 4

// encodedSecretForms returns the byte sequences the redactor should
// match for a given raw secret value: the raw bytes, plus base64 (std
// and URL-safe, padded and unpadded) and hex (lower and upper) forms.
// Empty values yield nil. Forms shorter than encodingMinRawLen-implied
// thresholds are filtered upstream by skipping the encoded set entirely
// for short secrets.
//
// Forms covered:
//
//	raw                      — verbatim bytes (always)
//	base64 std (padded)      — RFC 4648 §4, `+/` alphabet, `=` padding
//	base64 std (no padding)  — same alphabet, no `=` (common in JWTs)
//	base64 URL (padded)      — RFC 4648 §5, `-_` alphabet, `=` padding
//	base64 URL (no padding)  — same alphabet, no `=` (used in JWTs/JWS)
//	hex lower                — `0-9a-f` (most CLI tools default to this)
//	hex upper                — `0-9A-F` (some hex dumpers / Java toHex)
//
// Not covered (deliberate):
//
//	URL percent-encoding     — multiple flavors (PathEscape, QueryEscape,
//	                           RFC 3986 unreserved set); for typical API
//	                           keys the percent-encoded form equals the
//	                           raw (alphanumeric is reserved-set safe).
//	JSON-string escaping     — for alphanumeric/most-ASCII secrets the
//	                           escaped form equals the raw.
//	rot13 / other ciphers    — too many; out of scope.
//	entropy-based heuristics — false-positive prone on legitimate
//	                           hashes/UUIDs/tokens (file header gap #2).
func encodedSecretForms(raw []byte) [][]byte {
	if len(raw) == 0 {
		return nil
	}
	// Always include the raw form, even for tiny secrets — the raw match
	// is the load-bearing one. We only suppress the ENCODED expansions
	// below the length floor.
	forms := [][]byte{append([]byte(nil), raw...)}
	if len(raw) < encodingMinRawLen {
		return forms
	}
	// base64 — both alphabets, padded and unpadded. EncodeToString gives
	// the padded form; trimming trailing '=' yields the raw form, which
	// is also what RawStdEncoding / RawURLEncoding emit directly.
	stdPadded := base64.StdEncoding.EncodeToString(raw)
	urlPadded := base64.URLEncoding.EncodeToString(raw)
	stdRaw := base64.RawStdEncoding.EncodeToString(raw)
	urlRaw := base64.RawURLEncoding.EncodeToString(raw)
	// hex — lower (Go default) and upper (Java/some hexdumps).
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
