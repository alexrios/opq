# Adding a Backend

`opq` stores secrets through a `Backend` interface (`backend.go`). It ships two
implementations over `99designs/keyring`: the Linux Secret Service backend (libsecret over
D-Bus) and the macOS Keychain backend (login keychain via the Security framework). The
interface is shaped so additional backends drop in without touching anything else.

## The interface

```go
type Backend interface {
    Name() string
    Get(ctx context.Context, name string) (*Buffer, error)
    Set(ctx context.Context, name string, value *Buffer) error
    Delete(ctx context.Context, name string) error
    List(ctx context.Context) ([]string, error)
}
```

Contract notes. Return `ErrSecretNotFound` for misses, so `errors.Is(err,
ErrSecretNotFound)` works at the call site; the TTL/revocation layer and the MCP not-found
collapse both depend on this. `List` returns the raw keyspace, including companion
`meta/<name>` policy items, and callers handle those deliberately (see
[TTL Internals](../security/ttl-revocation.md)), so a new backend should not hide them.
`Get` returns a `memguard`-backed `*Buffer`, not raw bytes: move the secret into the
buffer (which wipes the source) and never log or copy it.

## Wiring it in

`OpenDefaultBackend` is implemented per-OS in build-tagged files (`backend_linux.go`,
`backend_darwin.go`, `backend_other.go`); the shared `keyringBackend` wrapper and the
`Backend` interface live in `backend.go`. Each platform opens `99designs/keyring`
restricted to a single entry in the `AllowedBackends` allowlist. Keep the allowlist tight,
and never silently fall back to an unencrypted file store: a backend that writes plaintext
to disk would void the threat model. If the chosen backend is unavailable, fail loudly
rather than degrading to an insecure one (the macOS file returns an actionable error when
the Keychain backend is missing because the build had CGO disabled).

## What's planned

Proton Pass (v2) needs a CLI/API shim. `pass`, file-based, and KWallet backends are
already reachable through the underlying `99designs/keyring` library; flip them on by
editing the relevant platform file's `AllowedBackends`, keeping the allowlist warning above
in mind for the file-based store.

## Testing a new backend

The existing unit tests run without a real keyring, using an in-memory fake. A new backend
should pass the shared `Backend` contract tests (round-trip `Set`/`Get`/`Delete`/`List`,
`ErrSecretNotFound` on a miss) and be exercised end-to-end on a host where the backend is
available. The macOS Keychain backend has a hermetic integration test
(`backend_darwin_integration_test.go`, run with `go test -tags integration`) that drives a
throwaway keychain in a temp dir so the login keychain is never touched.
