package main

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/99designs/keyring"
)

// Backend abstracts a secrets store. v1 ships one implementation
// (Secret Service via 99designs/keyring); future backends — macOS Keychain,
// Proton Pass — implement this same interface.
type Backend interface {
	Name() string
	Get(ctx context.Context, name string) (*Buffer, error)
	Set(ctx context.Context, name string, value *Buffer) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]string, error)
}

// ErrSecretNotFound is returned by Backend.Get when the named secret does not
// exist. Backends MUST translate their native not-found error to this
// sentinel so callers can match on it.
var ErrSecretNotFound = errors.New("secret not found")

const (
	serviceName    = "opq"
	collectionName = "opq"
)

// OpenDefaultBackend opens the platform-default backend. On Linux this is
// Secret Service (libsecret / gnome-keyring / KWallet via D-Bus). The list
// is intentionally restricted so we don't silently fall back to, e.g., an
// unencrypted file backend.
func OpenDefaultBackend() (Backend, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName:             serviceName,
		LibSecretCollectionName: collectionName,
		AllowedBackends: []keyring.BackendType{
			keyring.SecretServiceBackend,
			keyring.KeychainBackend, // for the future macOS build
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open keyring: %w", err)
	}
	return &keyringBackend{kr: kr, name: "secret-service"}, nil
}

type keyringBackend struct {
	kr   keyring.Keyring
	name string
}

func (b *keyringBackend) Name() string { return b.name }

func (b *keyringBackend) Get(_ context.Context, name string) (*Buffer, error) {
	item, err := b.kr.Get(name)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("keyring get: %w", err)
	}
	// item.Data is a []byte owned by the keyring lib. Move it into a locked
	// buffer (which wipes the source slice) so it never lingers on the heap.
	return NewBufferFromBytes(item.Data), nil
}

func (b *keyringBackend) Set(_ context.Context, name string, value *Buffer) error {
	if value == nil || !value.IsAlive() {
		return errors.New("set: empty value")
	}
	// Copy out to a transient slice for the keyring library; the library
	// will store it via the platform's secure storage path and we wipe
	// our local copy after the call returns.
	plain := value.Bytes()
	local := make([]byte, len(plain))
	copy(local, plain)
	defer wipe(local)

	err := b.kr.Set(keyring.Item{
		Key:         name,
		Data:        local,
		Label:       "opq:" + name,
		Description: "managed by opaque",
	})
	if err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

func (b *keyringBackend) Delete(_ context.Context, name string) error {
	if err := b.kr.Remove(name); err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return ErrSecretNotFound
		}
		return fmt.Errorf("keyring remove: %w", err)
	}
	return nil
}

func (b *keyringBackend) List(_ context.Context) ([]string, error) {
	keys, err := b.kr.Keys()
	if err != nil {
		return nil, fmt.Errorf("keyring keys: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}

// wipe overwrites s with zeros. Best-effort — Go's compiler may still optimize
// some cases, which is why secrets never live in plain []byte for long.
func wipe(s []byte) {
	for i := range s {
		s[i] = 0
	}
}

// sanitizeBackendErr maps any backend error to one of a fixed set of taxonomy
// keys that are safe to write to the audit log (and therefore safe for
// audit_tail to expose to an AI client). This prevents a buggy or
// future-malicious keyring backend from leaking secret bytes via the audit
// Message field.
//
// Taxonomy:
//
//	not_found      — ErrSecretNotFound
//	backend_error  — any other backend failure
func sanitizeBackendErr(err error) string {
	if errors.Is(err, ErrSecretNotFound) {
		return "not_found"
	}
	return "backend_error"
}
