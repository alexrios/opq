# TTL & Revocation Internals

> Implementation internals. For day-to-day usage start with the
> [TTL & Revocation tutorial](../tutorials/ttl-and-revocation.md).

The operator-facing behavior is in the
[TTL & Revocation tutorial](../tutorials/ttl-and-revocation.md). This page covers how it
works underneath: the single read path, the storage layout, and the invariants that keep
the AI from using policy state as an oracle. The code is `policy.go`.

## The single read path: resolveSecret

Every secret-value read goes through `resolveSecret(ctx, backend, name, now)`. It is the
one path used by `cmd_get.go`, `cmd_exec.go`, and the MCP `run_with_secrets` handler;
nothing calls `backend.Get(name)` directly for a value.

`resolveSecret`:

1. Re-runs `validSecretName(name)` as defense-in-depth, failing closed (as not-found) so
   a caller that forgot the guard cannot reach the `meta/` keyspace.
2. Takes a shared cross-process `policy.lock` and loads the companion `SecretMeta` item.
   Unknown metadata versions and pending updates fail closed.
3. Refuses revoked-then-expired (revoked beats expired, so the audit taxonomy reports the
   deliberate action) before fetching the value.
4. Returns the value only if no policy refuses it.

It is read-only: an expired secret is refused but not deleted, so the plaintext lingers in
the keyring until `opq prune` or `opq delete`. Only explicit `opq revoke` (and `prune`)
eagerly wipe. The read path does not write back to the keyring. It holds a shared policy
lock across metadata and value reads; mutations take the same lock exclusively. Lock waits honor the
request context. Native OS keyring calls cannot cancel an in-flight prompt; cancellation
is checked before and after the call, and returned secret bytes are destroyed if the
request was canceled. Expiry is checked again after waiting and fetching the value.

## Storage: companion keyring items

Policy metadata is not a sidecar database. It is a companion keyring item keyed
`meta/<name>`, stored alongside the value, so it is encrypted and backed up together. `/`
is illegal in a secret name (`validSecretName`), so the `meta/` namespace cannot collide
with a real secret. Metadata version 2 adds a `pending` update marker; existing version 1
records remain readable. `set` takes the exclusive lock, writes a pending metadata record first,
replaces the value, and only then commits the requested policy or removes metadata for a
plain no-TTL secret. A crash or failed value/final-policy write leaves the pending marker
in the encrypted keyring, so reads stay blocked. `opq list` shows `UPDATE-PENDING`.
Retry `opq set` to complete a replacement, or use `opq delete` to remove the interrupted
item. A failed preparation leaves the old value untouched. A successful plain `set`
clears prior policy, including a revoked tombstone, so it revives the name.

`revoke`, `delete`, and each prune check-and-delete also hold the exclusive lock. A
failed value deletion never clears its policy. Prune rechecks the current generation
under the lock and leaves revoked tombstones intact. `policy.lock` lives in
`<OS-account-home>/.local/state/opq-policy/` with mode `0600`, uses fresh non-symlink
file descriptors, and contains no credential data. Its home comes from the OS account
database, so clients with different `HOME` or `XDG_STATE_HOME` still share the same
lock. Sandbox profiles mask this directory separately from the configurable audit
location. All processes accessing the same keyring must use this protocol. Older opq
binaries do not understand pending updates and must not run concurrently with the
updated binary.

## parseTTL overflow guard

`parseTTL` bound-checks the day/week path in `float64` (rejecting NaN, Inf, and
`>= MaxInt64`) before the `int64` conversion, so a huge `--ttl` cannot wrap around to a
past expiry.

## backend.List and the meta/ keyspace

`backend.List` returns the raw keyspace, including `meta/` keys. Each consumer handles
them deliberately: `cmd_list.go` surfaces them as status on the parent name (and shows
`meta-error` on an unreadable item rather than a false "live"); `cmd_prune.go` enumerates
them to find expired secrets; and the MCP `handleListSecrets` routes through
`filterVisibleSecretNames` so the AI never sees the `meta/` scheme or a revoked tombstone.

## The not-found collapse

The AI-facing `run_with_secrets` error collapses revoked, expired, and not_found into a
single `not_found` token. Distinguishing them would re-leak, via the error taxonomy, the
tombstone existence that `filterVisibleSecretNames` hides. The precise reason
(`secret_revoked` / `secret_expired`, as a bare token via `sanitizePolicyErr`) goes to the
operator audit only.

## Why use-count limits are not here

Use-count limits were evaluated and declined. They are the only TTL follow-up with unique
value, but they break the read-only read path: every resolve would need a write-back plus
a cross-process counter lock, and the cost outweighs the value for v1. Absolute
`--expires-at` (sugar over `--ttl`) and a resident auto-destruction daemon (a cron `opq
prune` recipe instead) were likewise declined. The shipped time-based TTL plus `revoke`
covers the real operator need; compromise of the logged-in keyring session remains total
compromise regardless.

Locked by `policy_test.go`.
