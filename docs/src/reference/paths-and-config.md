# Paths & Configuration

`opq` has little configuration of its own; it relies on the OS keyring and a few
well-known paths, tuned through a small set of environment variables.

## Filesystem paths

| Path | Purpose |
| --- | --- |
| `${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log` | The audit log (mode `0600`). |
| `…/opq/audit.log.1` | One historical rotation, kept when the active log passes 10 MiB. |
| `…/opq/audit.lock` | The cross-process flock file (never rotated). |

Secrets are not stored on disk by `opq`; they live in the OS keyring (Secret Service /
libsecret on Linux) under the `opq` service name and collection. Policy metadata is a
companion keyring item keyed `meta/<name>`.

## Environment variables

### Consumed by `opq`

| Variable | Effect |
| --- | --- |
| `OPQ_I_AM_HUMAN=1` | Required (inline on the command) for `opq get --plaintext` and `opq exec --no-redact`. Part of the human-confirmation gate. |
| `XDG_STATE_HOME` | Overrides the base directory for the audit log. |
| `HOME` | Resolves `~/.local/state` and the home-directory socket masks under SandboxNet. |

All `opq`-specific variables use the `OPQ_*` prefix.

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
[policy proxy](../tutorials/sandbox-and-hardening.md#the-policy-proxy-pattern). Backend
selection is not a runtime option either; the allowed-backends list is compiled into
`OpenDefaultBackend`, and adding one means editing `AllowedBackends` (see
[Adding a Backend](../appendix/backends.md)).

## Build, test, run

```sh
go build -o opq .      # or: mise run build  → dist/opq
go test ./...          # all unit tests (no network, no keyring required)
go vet ./...
```

The repo uses [`mise`](https://mise.jdx.dev/) for tasks: `mise run check` is the
pre-commit gate (vet + test + build), and `mise run docs` builds this book. End-to-end
smoke testing requires an unlocked Secret Service session.
