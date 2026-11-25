# TTL & Revocation

Secrets are durable by default; once set, they stay usable until removed. Two things
bound a secret's life: a time-based TTL, and explicit revocation. `prune` sweeps
expired ones (and optionally revoked tombstones). The internals are in
[TTL & Revocation Internals](../security/ttl-revocation.md); this page covers usage.

## Secret lifecycle

<figure class="opq-diagram">
<svg role="img" aria-labelledby="lifecycle-title lifecycle-desc" viewBox="0 0 720 356" xmlns="http://www.w3.org/2000/svg">
  <title id="lifecycle-title">opq Secret Lifecycle State Machine</title>
  <desc id="lifecycle-desc">State transitions between Not Stored, Active, UPDATE-PENDING, EXPIRED, REVOKED tombstone, and Removed states via set, revoke, prune, and delete commands.</desc>
  <defs>
    <marker id="lc-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" class="svg-arrow-head"/>
    </marker>
  </defs>
  <rect x="14" y="20" width="126" height="68" rx="8" class="svg-box-dashed"/>
  <text x="77" y="49" text-anchor="middle" class="svg-title">Not Stored</text>
  <text x="77" y="67" text-anchor="middle" class="svg-sub">Absent / new</text>
  <line x1="140" y1="54" x2="231" y2="54" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="186" y="45" text-anchor="middle" class="svg-edge-label">set [--ttl]</text>
  <rect x="234" y="20" width="232" height="68" rx="8" class="svg-box-tip"/>
  <text x="350" y="42" text-anchor="middle" class="svg-title">Active</text>
  <text x="350" y="59" text-anchor="middle" class="svg-sub">Readable via resolveSecret</text>
  <text x="350" y="75" text-anchor="middle" class="svg-mono">set --keep-ttl rotates value</text>
  <line x1="466" y1="40" x2="551" y2="40" class="svg-edge-dashed" marker-end="url(#lc-arrow)"/>
  <text x="510" y="32" text-anchor="middle" class="svg-edge-label">set fails</text>
  <line x1="554" y1="68" x2="469" y2="68" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="510" y="83" text-anchor="middle" class="svg-edge-label">retry set</text>
  <rect x="554" y="20" width="152" height="68" rx="8" class="svg-box-important"/>
  <text x="630" y="45" text-anchor="middle" class="svg-title">UPDATE-PENDING</text>
  <text x="630" y="62" text-anchor="middle" class="svg-sub">Reads blocked</text>
  <text x="630" y="77" text-anchor="middle" class="svg-sub">Interrupted set</text>
  <line x1="256" y1="88" x2="256" y2="165" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="247" y="131" text-anchor="end" class="svg-edge-label">TTL lapses</text>
  <line x1="298" y1="168" x2="298" y2="91" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="307" y="131" text-anchor="start" class="svg-edge-label">set</text>
  <line x1="414" y1="168" x2="414" y2="91" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="405" y="131" text-anchor="end" class="svg-edge-label">set</text>
  <line x1="452" y1="88" x2="452" y2="165" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="461" y="131" text-anchor="start" class="svg-edge-label">revoke</text>
  <rect x="44" y="168" width="276" height="64" rx="8" class="svg-box-warn"/>
  <text x="182" y="191" text-anchor="middle" class="svg-title">EXPIRED</text>
  <text x="182" y="208" text-anchor="middle" class="svg-sub">Reads refused (secret has expired)</text>
  <text x="182" y="223" text-anchor="middle" class="svg-sub">Value lingers until prune / delete</text>
  <line x1="320" y1="200" x2="393" y2="200" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="358" y="192" text-anchor="middle" class="svg-edge-label">revoke</text>
  <rect x="396" y="168" width="256" height="64" rx="8" class="svg-box-caution"/>
  <text x="524" y="191" text-anchor="middle" class="svg-title">REVOKED (tombstone)</text>
  <text x="524" y="208" text-anchor="middle" class="svg-sub">Value wiped immediately</text>
  <text x="524" y="223" text-anchor="middle" class="svg-sub">Tombstone stays in keyring</text>
  <line x1="140" y1="232" x2="140" y2="289" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="150" y="266" text-anchor="start" class="svg-edge-label">prune / delete</text>
  <line x1="548" y1="232" x2="548" y2="289" class="svg-edge" marker-end="url(#lc-arrow)"/>
  <text x="538" y="266" text-anchor="end" class="svg-edge-label">prune --include-revoked / delete</text>
  <line x1="682" y1="88" x2="682" y2="289" class="svg-edge-dashed" marker-end="url(#lc-arrow)"/>
  <text x="673" y="131" text-anchor="end" class="svg-edge-label">delete</text>
  <rect x="44" y="292" width="662" height="50" rx="8" class="svg-box-dashed"/>
  <text x="375" y="314" text-anchor="middle" class="svg-title">Removed from keyring (value &amp; metadata deleted)</text>
  <text x="375" y="331" text-anchor="middle" class="svg-sub">opq delete &lt;name&gt;... removes a secret directly from any state</text>
</svg>
<figcaption>Lifecycle states enforced by <code>resolveSecret</code>. Over MCP, <code>EXPIRED</code>, <code>REVOKED</code>, <code>UPDATE-PENDING</code>, and absent names all collapse to <code>not_found</code> so the error channel cannot act as a policy-state oracle.</figcaption>
</figure>

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
# → opq: resolve ci_token: secret has expired
```

`opq list` shows the expiry while it is live, and flips to `EXPIRED` afterward:

```sh
opq list
# ci_token   expires in 24h (2026-06-08 12:00 UTC)
# ... later ...
# ci_token   EXPIRED
```

TTL is access control, not auto-destruction. Expiry is enforced lazily on read and
never mutates the keyring, so the plaintext stays in the keyring until you sweep it
with [`prune`](#prune) or `delete` it. There is no resident daemon watching the clock;
for eager destruction, run `opq prune` from cron or a systemd timer.

### Re-setting clears or keeps the old policy

A plain `opq set NAME` (with no `--ttl` or `--keep-ttl`) clears any prior policy on that
name, including a revoked tombstone, so re-setting a secret revives it cleanly.

To rotate a secret's value while preserving its existing unexpired deadline, pass
`--keep-ttl`:

```sh
printf 'sk-rotated-ZZZZ' | opq set ci_token --keep-ttl
```

`--keep-ttl` cannot be combined with `--ttl` and fails if the secret has no active,
unexpired TTL.

## Interrupted updates

From v1.3.0, `set` marks an update pending before replacing the stored value. If the
process crashes or the backend cannot finish the policy write, reads stay blocked and
`opq list` shows `UPDATE-PENDING`. Retry `opq set NAME` with the intended value and TTL,
or explicitly delete the interrupted item. All clients of the same keyring must be
upgraded together; older clients do not understand this marker.

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
expired secret (value and policy). By default, `REVOKED` tombstones are preserved so
operators keep a record that the name was revoked; pass `--include-revoked` to remove
tombstones as well:

```sh
opq prune --dry-run                    # preview expired secrets that would be deleted
opq prune                              # delete expired secrets
opq prune --include-revoked --dry-run  # preview expired secrets + REVOKED tombstones
opq prune --include-revoked            # delete expired secrets and REVOKED tombstones
```

`opq prune` finishes its sweep and exits non-zero if any item fails to delete, so
scheduled jobs surface failures cleanly. A common setup runs `opq prune` from cron or a
systemd timer so expired plaintext does not accumulate:

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
| Rotate value, keep expiry | `opq set NAME --keep-ttl` | Replaces value while preserving active unexpired TTL. |
| Kill a leaked secret now | `opq revoke NAME` | Value wiped immediately; tombstone left. |
| Sweep expired plaintext | `opq prune` | Deletes all expired secrets. |
| Sweep expired + tombstones | `opq prune --include-revoked` | Deletes expired secrets and `REVOKED` tombstones. |
| Remove everything for a name | `opq delete NAME` | Value and policy gone (accepts multiple names). |
| Revive a revoked/expired name | `opq set NAME` | Clears prior policy; name usable again. |
