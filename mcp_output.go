// Package main: bounded subprocess output. Redaction prevents accidental
// disclosure; arbitrary output content and length remain information channels.
package main

import (
	"io"
	"sync"
)

// cappedWriter forwards bytes to an inner writer up to a fixed cap,
// then silently drops further bytes and records a truncated flag. It
// is the outermost layer of the run_with_secrets output pipeline and
// exists solely to bound memory growth; bytes that reach this writer
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
