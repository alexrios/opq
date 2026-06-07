# TTL & Revocation

Secrets are durable by default; once set, they stay usable until removed. Two things
bound a secret's life: a time-based TTL, and explicit revocation. `prune` sweeps
expired ones. The internals are in
[TTL & Revocation Internals](../security/ttl-revocation.md); this page covers usage.

## TTL: expire on a timer

Attach a time-to-live when you set the secret:

```sh
printf 'sk-rotating-XXXX' | opq set ci_token --ttl 24h
```

Accepted formats include `90m`, `24h`, `7d`, and `2w`. After the TTL lapses, every read
path refuses the value: `opq get`, `opq exec`, and the MCP `run_with_secrets` tool all
fail closed.

```sh
# After 24h:
opq exec --env TOK=ci_token -- ./deploy.sh
# → error: secret not available
```

`opq list` shows the expiry while it is live, and flips to `EXPIRED` afterward:

```sh
opq list
# ci_token   expires 2026-06-08T12:00:00Z
# ... later ...
# ci_token   EXPIRED
```

TTL is access control, not auto-destruction. Expiry is enforced lazily on read and
never mutates the keyring, so the plaintext stays in the keyring until you sweep it
with [`prune`](#prune) or `delete` it. There is no resident daemon watching the clock;
for eager destruction, run `opq prune` from cron or a systemd timer.

### Re-setting clears the old policy

A plain `opq set NAME` (no `--ttl`) clears any prior policy on that name, including a
revoked tombstone, so re-setting a secret revives it cleanly.

## Revocation: kill it now

`opq revoke` is for a leaked secret. Unlike TTL expiry, it wipes the value from the
keyring immediately and leaves a revoked tombstone:

```sh
opq revoke ci_token
```

After revocation, `get` / `exec` / MCP reads all refuse the value, `opq list` shows the
name as `REVOKED` (distinct from never-existed), and the plaintext is already gone from
the keyring.

Re-set the name to bring it back (clears the tombstone):

```sh
printf 'sk-fresh-YYYY' | opq set ci_token
```

Or remove the record entirely:

```sh
opq delete ci_token
```

## prune

TTL expiry leaves the plaintext in the keyring until swept. `opq prune` deletes every
expired secret (value and policy):

```sh
opq prune --dry-run    # preview what would be deleted
opq prune              # delete expired secrets
```

A common setup runs `opq prune` from cron or a systemd timer so expired plaintext does
not accumulate:

```cron
# Sweep expired opq secrets every hour
0 * * * * /usr/local/bin/opq prune
```

## What the AI sees

The MCP surface never exposes policy state. `list_secrets` filters out the internal
policy items, and `run_with_secrets` collapses revoked, expired, and missing into a
single `not_found`, so an AI cannot use the error taxonomy as a state oracle. The
precise reason (`secret_revoked` / `secret_expired`) is recorded in the operator's
audit log only.

## Summary

| Goal | Command | Effect |
| --- | --- | --- |
| Expire on a timer | `opq set NAME --ttl 24h` | Reads refused after expiry; value lingers until swept. |
| Kill a leaked secret now | `opq revoke NAME` | Value wiped immediately; tombstone left. |
| Sweep expired plaintext | `opq prune` | Deletes all expired secrets. |
| Remove everything for a name | `opq delete NAME` | Value and policy gone. |
| Revive a revoked/expired name | `opq set NAME` | Clears prior policy; name usable again. |
