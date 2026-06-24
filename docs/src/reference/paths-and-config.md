# Paths & Configuration

`opq` has little configuration of its own; it relies on the OS keyring and a few
well-known paths, tuned through a small set of environment variables.

## Filesystem paths

| Path | Purpose |
| --- | --- |
| `${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log` | The audit log (mode `0600`). |
| `…/opq/audit.log.1` | One historical rotation, kept when the active log passes 10 MiB. |
| `…/opq/audit.lock` | The cross-process flock file (never rotated). |

With the default keyring backend, secrets are not stored on disk by `opq`; they live in the
OS keyring (Secret Service / libsecret on Linux) under the `opq` service name and collection.
Policy metadata is a companion item keyed `meta/<name>`. Other [backends](../appendix/backends.md)
(Vault, Proton Pass) keep secrets in their own systems.

## Environment variables

### Consumed by `opq`

| Variable | Effect |
| --- | --- |
| `OPQ_I_AM_HUMAN=1` | Required (inline on the command) for `opq get --plaintext` and `opq exec --no-redact`. Part of the human-confirmation gate. |
| `XDG_STATE_HOME` | Overrides the base directory for the audit log. |
| `HOME` | Resolves `~/.local/state` and the home-directory socket masks under SandboxNet. |

All `opq`-specific variables use the `OPQ_*` prefix.

### Backend selection

`opq` reads the OS keyring by default. `--backend` or `OPQ_BACKEND` chooses another store;
see [Backends](../appendix/backends.md).

| Variable | Effect |
| --- | --- |
| `OPQ_BACKEND` | Backend when `--backend` is omitted: `keyring` (default), `vault`, or `proton-pass`. |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` | Vault address, token, and optional namespace (standard Vault vars). |
| `OPQ_VAULT_MOUNT`, `OPQ_VAULT_PREFIX` | Vault KV v2 mount (default `secret`) and path prefix (default `opq`). |
| `OPQ_VAULT_ALLOW_INSECURE_HTTP` | Set to `1` to allow a plaintext `http://` `VAULT_ADDR` (default: https is required). |
| `OPQ_PROTON_VAULT` | Proton Pass vault name to read (required for `proton-pass`). |
| `OPQ_PROTON_FIELD` | Proton item field to read (default `password`). |
| `OPQ_PROTON_PASS_CLI` | Path to the `pass-cli` binary (default: found on `PATH`). |

`VAULT_TOKEN`, `PROTON_PASS_PERSONAL_ACCESS_TOKEN`, and `PROTON_PASS_ENCRYPTION_KEY` are
scrubbed from `opq exec` child environments so a subprocess cannot read them.

### Honored by the keyring layer

The Secret Service backend talks to your session keyring over D-Bus, so the usual
freedesktop variables apply (`DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`). If
`opq list` fails with a D-Bus error, your keyring session is not unlocked; see
[Installation](../getting-started/installation.md#verifying-the-install).

## Not configurable in v1

By design (see [Design Decisions](../security/design-decisions.md)), there is no config
file: no `opq.toml` or dotfile. The deny-list, sandbox masks, and limits are compiled in
so a writable config cannot weaken them. There is no per-project allowlist; that policy
belongs in a deployment-side
[policy proxy](../tutorials/sandbox-and-hardening.md#the-policy-proxy-pattern). Backends are
selectable at runtime via `--backend`/`OPQ_BACKEND`, but only from a compiled-in allowlist
(`openBackend`); an unknown name is rejected rather than falling back to a file store (see
[Backends](../appendix/backends.md)).

## Building from source

Build-from-source steps are in
[Installation](../getting-started/installation.md#build-from-source). The contributor
workflow (tests, `go vet`, the [`mise`](https://mise.jdx.dev/) task runner, and building
this book) lives in the repo's `CLAUDE.md` and the
[Version History](../appendix/version-history.md#re-verifying) appendix.
