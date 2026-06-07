# Adding a Backend

`opq` stores secrets through a `Backend` interface (`backend.go`). v1 ships the Linux
Secret Service backend (libsecret over D-Bus). The interface is shaped so additional
backends drop in without touching anything else.

## The interface

```go
type Backend interface {
    Name() string
    Get(name string) ([]byte, error)
    Set(name string, value []byte) error
    Delete(name string) error
    List() ([]string, error)
}
```

Contract notes. Return `ErrSecretNotFound` for misses, so `errors.Is(err,
ErrSecretNotFound)` works at the call site; the TTL/revocation layer and the MCP not-found
collapse both depend on this. `List()` returns the raw keyspace, including companion
`meta/<name>` policy items, and callers handle those deliberately (see
[TTL Internals](../security/ttl-revocation.md)), so a new backend should not hide them.
`Get` returns raw bytes; the caller wraps them in a `memguard` buffer, so the backend
should not log or copy them.

## Wiring it in

Backend selection happens in `OpenDefaultBackend`. Add your backend to the
`AllowedBackends` allowlist there. Keep the allowlist tight, and never silently fall back
to an unencrypted file store: a backend that writes plaintext to disk would void the
threat model. If a chosen backend is unavailable, fail loudly rather than degrading to an
insecure one.

## What's planned

macOS Keychain (v1.2) is mostly free via `99designs/keyring`; the main work is wiring and
platform testing. Proton Pass (v2) needs a CLI/API shim. `pass`, file-based, and KWallet
backends are already reachable through the underlying `99designs/keyring` library; flip
them on by editing `AllowedBackends`, keeping the allowlist warning above in mind for the
file-based store.

## Testing a new backend

The existing unit tests run without a real keyring, using an in-memory fake. A new backend
should pass the shared `Backend` contract tests (round-trip `Set`/`Get`/`Delete`/`List`,
`ErrSecretNotFound` on a miss) and be exercised end-to-end with `mise run smoke` on a host
where the backend is available.
