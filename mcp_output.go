// Package main — run_with_secrets output pipeline.
//
// Two layers sit downstream of the redactor: cappedWriter bounds memory by
// dropping bytes past a fixed cap (and recording a truncated flag for the
// operator audit), and quantizeOutputForAI pads the AI-visible stream lengths
// to coarse buckets so len(stdout) leaks far fewer secret bits per call
// (gap #3 in the mcp.go header).
package main

import (
	"io"
	"strings"
	"sync"
)

// outputBuckets is the closed set of stdout/stderr lengths the AI may
// observe in a run_with_secrets response. Every non-empty stream is
// padded up to the smallest bucket >= its real length. The cap value
// (mcpMaxOutputBytes) MUST be present as the final entry — outputs at
// the cap have already been truncated by cappedWriter and need no
// padding. Earlier buckets follow the geometric power-of-two ladder
// 1 KiB → 4 KiB → 16 KiB → 64 KiB so a small command's response is not
// inflated more than ~4x while the channel remains coarse-grained.
//
// Bits leaked per call (worst case, adversary controls the volume
// function): log2(len(outputBuckets)) bits per stream — today
// log2(5) ≈ 2.3 bits, down from ~17 bits (262144 distinct lengths).
// Recovering one 8-bit secret byte under this regime requires ~4 calls
// instead of 1; expanding the bucket set (more granularity) would
// invert that trade. Do not add intermediate buckets without justifying
// the per-call channel rate against the bandwidth cost.
//
// Empty (len==0) streams are NOT padded; an empty result is a coarse
// 1-bit signal (command emitted nothing) already implicit in the
// AI-controlled command and not worth the bandwidth cost of always
// emitting at least 1 KiB.
var outputBuckets = []int{1024, 4096, 16384, 65536, mcpMaxOutputBytes}

// outputPadMarker is the visible token appended once at the boundary
// between real output and padding. Tooling consuming the response can
// scan for this token and strip the trailing padding. The marker plus
// padding are bytes inside the JSON string value, so a naive
// byte-counter (`len(stdout)`) sees the bucket-quantized total — that
// is the whole point. The marker length is short enough that the
// smallest pad gap (4 bytes when n is 1020 and bucket is 1024) can
// fall below it; in that case we emit only space-padding without the
// marker. The marker bytes themselves are constant across calls and
// therefore not a channel.
const outputPadMarker = "\n[opq-pad]\n"

// nextOutputBucket returns the smallest bucket >= n, or n if n is
// already at or above the largest bucket (which equals mcpMaxOutputBytes).
func nextOutputBucket(n int) int {
	for _, b := range outputBuckets {
		if n <= b {
			return b
		}
	}
	return n
}

// quantizeOutputForAI pads s up to the next outputBuckets boundary so the
// AI-visible len(s) does not reveal fine-grained per-byte information
// about a subprocess output volume. Empty input is returned unchanged
// (see outputBuckets godoc for why). When the padding gap is large
// enough, an `[opq-pad]` marker is included once so AI tooling can
// recognize the suffix as padding; smaller gaps emit only spaces.
//
// Padding is byte-quantized to the bucket length: the returned string
// length is exactly bucket if s was non-empty. Tests verify this
// invariant — do not break it by adding "if pad <= 0 return s" style
// short-circuits past the initial empty check.
func quantizeOutputForAI(s string) string {
	if len(s) == 0 {
		return s
	}
	bucket := nextOutputBucket(len(s))
	pad := bucket - len(s)
	if pad <= 0 {
		return s
	}
	if pad >= len(outputPadMarker) {
		return s + outputPadMarker + strings.Repeat(" ", pad-len(outputPadMarker))
	}
	return s + strings.Repeat(" ", pad)
}

// cappedWriter forwards bytes to an inner writer up to a fixed cap,
// then silently drops further bytes and records a truncated flag. It
// is the outermost layer of the run_with_secrets output pipeline and
// exists solely to bound memory growth — bytes that reach this writer
// have already been through the redactor.
type cappedWriter struct {
	mu        sync.Mutex
	inner     io.Writer
	remaining int
	truncated bool
}

func newCappedWriter(inner io.Writer, limit int) *cappedWriter {
	return &cappedWriter{inner: inner, remaining: limit}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) <= c.remaining {
		n, err := c.inner.Write(p)
		c.remaining -= n
		return n, err
	}
	// Partial: write what fits, drop the rest, flip the flag.
	take := p[:c.remaining]
	n, err := c.inner.Write(take)
	c.remaining -= n
	c.truncated = true
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// Truncated reports whether any bytes were dropped due to the cap.
func (c *cappedWriter) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}
