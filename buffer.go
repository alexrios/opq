package main

import (
	"bytes"
	"errors"
	"io"

	"github.com/awnumar/memguard"
)

// Buffer wraps a memguard.LockedBuffer so the rest of the codebase never
// touches a raw []byte or string that holds a secret value. Pages backing
// the buffer are mlocked and zeroed on Destroy.
type Buffer struct {
	inner *memguard.LockedBuffer
}

// ErrSecretContainsNUL is returned when a secret value carries a NUL byte.
// os/exec rejects env entries with NUL before execve, so a NUL-bearing secret is
// unusable in every opq workflow; rejecting at the constructor turns an opaque
// runtime "exec_start_failed" into a clear error at `opq set`.
var ErrSecretContainsNUL = errors.New("secret value contains NUL byte (not usable as an environment variable; reject at source)")

// NewBufferFromBytes copies src into a locked buffer and wipes src in place.
// Callers MUST stop using src after this call. Returns an error if src is
// empty (memguard.NewBuffer(0) returns nil, and Move on nil panics) or if
// src contains a NUL byte (see ErrSecretContainsNUL).
func NewBufferFromBytes(src []byte) (*Buffer, error) {
	if len(src) == 0 {
		return nil, errors.New("empty secret value")
	}
	if bytes.IndexByte(src, 0) >= 0 {
		return nil, ErrSecretContainsNUL
	}
	b := memguard.NewBuffer(len(src))
	b.Move(src)
	return &Buffer{inner: b}, nil
}

// NewBufferFromReader reads r to EOF into a locked buffer. The caller must
// bound r (e.g. via io.LimitReader) to prevent unbounded allocation. Same
// NUL-byte rejection as NewBufferFromBytes.
func NewBufferFromReader(r io.Reader) (*Buffer, error) {
	lb, err := memguard.NewBufferFromEntireReader(r)
	if err != nil {
		if lb != nil {
			lb.Destroy()
		}
		return nil, err
	}
	if lb == nil || lb.Size() == 0 {
		if lb != nil {
			lb.Destroy()
		}
		return nil, errors.New("empty secret value")
	}
	if bytes.IndexByte(lb.Bytes(), 0) >= 0 {
		lb.Destroy()
		return nil, ErrSecretContainsNUL
	}
	return &Buffer{inner: lb}, nil
}

// Bytes exposes the underlying secret bytes. The returned slice is only valid
// until Destroy is called and MUST NOT be retained, copied to a string, or
// logged. Intended for: handing to os/exec env construction, writing to stdin
// of a trusted subprocess, or constructing the redactor's secret list.
func (b *Buffer) Bytes() []byte {
	if b == nil || b.inner == nil {
		return nil
	}
	return b.inner.Bytes()
}

// Size returns the secret length in bytes.
func (b *Buffer) Size() int {
	if b == nil || b.inner == nil {
		return 0
	}
	return b.inner.Size()
}

// Destroy zeroes and frees the underlying locked pages. Safe to call multiple
// times. After Destroy, Bytes returns nil.
func (b *Buffer) Destroy() {
	if b == nil || b.inner == nil {
		return
	}
	b.inner.Destroy()
	b.inner = nil
}

// IsAlive reports whether the buffer still holds valid data.
func (b *Buffer) IsAlive() bool {
	return b != nil && b.inner != nil && b.inner.IsAlive()
}
