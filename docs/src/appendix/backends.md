# Backends

`opq` stores secrets through a `Backend` interface (`backend.go`) and ships three:

| `--backend` / `$OPQ_BACKEND` | Storage | Mode |
| --- | --- | --- |
| `keyring` (default) | OS keyring: Secret Service / libsecret on Linux, Keychain on macOS | read-write |
| `vault` | HashiCorp Vault KV v2 (thin `net/http` client, no SDK) | read-write |
| `proton-pass` | Proton Pass, via the official `pass-cli` binary | read-only |

Pick a backend per invocation with `--backend <name>` or the `OPQ_BACKEND` env var (the
flag wins). Unset means `keyring`. An unknown name is a hard error: `opq` never silently
falls back to a less secure store. Redaction and the subprocess sandbox are independent of
the backend, so the core "an AI never sees plaintext" guarantee holds for all three.

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

Contract notes. Return `ErrSecretNotFound` for misses, so `errors.Is(err, ErrSecretNotFound)`
works at the call site; the TTL/revocation layer and the MCP not-found collapse depend on
it. A read-only backend returns `ErrBackendReadOnly` from `Set`/`Delete`. `List()` returns
the raw keyspace, including companion `meta/<name>` policy items, and callers handle those
deliberately (see [TTL Internals](../security/ttl-revocation.md)), so a new backend should
not hide them. Values move through `*Buffer` (memguard-locked); a backend wipes any transient
plaintext copy it makes and never logs a value.

## HashiCorp Vault

Reads and writes a KV **v2** mount. Configure with the standard `VAULT_ADDR`, `VAULT_TOKEN`,
and optional `VAULT_NAMESPACE`, plus `OPQ_VAULT_MOUNT` (default `secret`) and
`OPQ_VAULT_PREFIX` (default `opq`). Each secret lives at `<mount>/<prefix>/<name>` with the
value base64'd under a single `value` field, so binary values round-trip. `revoke`, `prune`,
and `delete` destroy **all** versions (`DELETE …/metadata/…`), not a recoverable soft delete.
The mount must be KV v2; v1 is unsupported. `VAULT_ADDR` must be `https://` (over plaintext
the token and values would cross the network in the clear); set
`OPQ_VAULT_ALLOW_INSECURE_HTTP=1` to permit an `http://` endpoint such as a localhost dev
server.

## Proton Pass (read-only)

Reads secrets you manage in the Proton Pass app by shelling out to the official
[`pass-cli`](https://protonpass.github.io/pass-cli/). `get`, `list`, `exec`, and
`run_with_secrets` work; `set`, `revoke`, `prune`, and `--ttl` return a read-only error
(manage items in the Pass app instead). Configure with `OPQ_PROTON_VAULT` (required — the
vault name to read), `OPQ_PROTON_FIELD` (default `password`), and optionally
`OPQ_PROTON_PASS_CLI` (the binary path). Authenticate `pass-cli` first, e.g.
`PROTON_PASS_PERSONAL_ACCESS_TOKEN=… pass-cli login`; `opq` does not manage that session.
Requires a paid Proton plan. Because policy items can't be written, a Proton secret has no
TTL/revocation. opq addresses items by title, so each title must be unique within the vault;
if two items share a title, opq refuses to return either (rename one in the Pass app). Only
titles matching opq's secret-name rules (`[A-Za-z0-9_.-]`, no spaces) can be referenced by
`get`/`exec`; others are listed but not addressable. A
value that ends in a newline can't round-trip through `pass-cli --field`; store such a value
in the keyring or Vault instead.

## Credential hygiene

The secret credentials `opq` reads to reach a backend — `VAULT_TOKEN`,
`PROTON_PASS_PERSONAL_ACCESS_TOKEN`, `PROTON_PASS_ENCRYPTION_KEY` — are scrubbed from the
environment of any child `opq exec` spawns, so a subprocess can't read them from `$VAULT_TOKEN`
and exfiltrate the master key to the whole store. Non-secret config (`VAULT_ADDR`, …) is left
in place. The MCP `run_with_secrets` child already starts from an empty parent environment.

## Wiring in a new backend

Selection lives in `openBackend` (`backend_select.go`), a tight allowlist keyed by name;
`OpenDefaultBackend()` resolves the no-arg form from the `--backend`/`OPQ_BACKEND` selector.
Add a `case` for the new backend. Keep the allowlist tight, never silently fall back to an
unencrypted file store, and fail loudly if a chosen backend is unavailable. `pass`,
file-based, and KWallet stores are reachable through the underlying `99designs/keyring`
library by extending the keyring allowlist (mind the file-store warning).

macOS Keychain (v1.2) is mostly free via `99designs/keyring`; the remaining work is wiring
and platform testing.

## Testing a new backend

Unit tests run without a real keyring, Vault, or `pass-cli`: Vault uses an `httptest` KV v2
fake, Proton an injected command runner, the keyring an in-memory fake. A new backend should
pass the shared `backendContractTest` (round-trip `Set`/`Get`/`Delete`/`List`,
`ErrSecretNotFound` on a miss, `meta/` coexistence for writable backends) and be exercised
end-to-end with `mise run smoke` on a host where the backend is available.
