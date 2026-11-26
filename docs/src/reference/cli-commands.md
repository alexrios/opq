# CLI Commands

The complete `opq` command surface. Secret operations are recorded in the
[audit log](./audit-log.md); `opq audit`, `opq info`, `opq doctor`, and `opq completion`
do not read secret values, and `opq audit` is a read-only view that does not log itself.

| Command | Behavior |
| --- | --- |
| `opq set <name> [--ttl <dur>] [--keep-ttl] [--no-clobber] [--trim]` | Read value from stdin (or hidden TTY prompt). Never accepts values on argv. |
| `opq list [--long\|-l] [--json] [--status <state>]` | Print stored secret names and policy state; never reads values. |
| `opq info <name> [--json]` | Inspect metadata for one secret (backend, status, timestamps) without reading its value. |
| `opq get <name> --plaintext` | Print value to stdout. Refuses unless stdout is a TTY (plus the human gate, below). |
| `opq exec -e VAR[=name] [...] [--sandbox none\|net\|full] [--no-redact] -- cmd` | Run `cmd` with named secrets injected as env vars. Output redacted by default. |
| `opq delete <name>...` | Remove one or more secrets and their TTL/revocation records. |
| `opq revoke <name>` | Wipe a secret's value immediately and leave a revoked tombstone. |
| `opq prune [--dry-run] [--include-revoked]` | Delete expired secrets (and optionally `REVOKED` tombstones). `--dry-run` previews. |
| `opq audit [-n N] [--all] [--json] [--caller ...] [--action ...] [--secret ...]` | Inspect audit-log entries (aligned table on TTY, JSONL on pipe or `--json`). |
| `opq doctor [--json]` | Run read-only health checks on binary, keyring/vault, OS sandbox, audit log, and policy state. |
| `opq migrate [--dry-run] [--overwrite] [--delete-legacy]` | Migrate legacy macOS Keychain items (`service="opq"`) into the encrypted local vault while preserving TTL and revocation metadata. |
| `opq completion <bash\|zsh\|fish>` | Print a shell completion script for subcommands, flags, and secret names. |
| `opq mcp` | Run as a Model Context Protocol server over stdio. |

## `opq set`

```sh
opq set <name> [--ttl <duration>] [--keep-ttl] [--no-clobber] [--trim]
```

Reads the value from stdin if stdin is a pipe or file, or prompts on the hidden TTY if
stdin is a terminal (nothing echoes as you type). Values are never read from argv.

Names match `[A-Za-z0-9_.-]{1,128}`: no slashes (the `/` namespace is reserved for
internal policy items), no spaces. NUL-bearing values are rejected, since `os/exec`
cannot pass them as env entries anyway.

| Flag | Behavior |
| --- | --- |
| `--ttl <duration>` | Sets a time-to-live (`90m`, `24h`, `7d`, `2w`, etc.). Writes a pending companion item before replacing the value and commits the policy afterward. |
| `--keep-ttl` | Preserves the existing non-expired `ExpiresAt` deadline when rotating a secret's value. Rejected if combined with `--ttl` or if the secret has no active, unexpired TTL. |
| `--no-clobber` | Refuses to overwrite an existing live secret. |
| `--trim` | Strips trailing `\r\n` and `\n` from piped stdin. |

- **Piped vs. interactive whitespace:** The interactive prompt disables bracketed-paste
  mode and trims surrounding whitespace. The piped path stores bytes verbatim by default
  so whitespace-significant values work; if piped input ends with `\n` or `\r\n` and
  `--trim` is not passed, `opq` writes a warning to stderr (`warning: stored value ends
  with a newline; use printf instead of echo or pass --trim`).
- **Overwrite and state notices:** Before storing (and before prompting in interactive
  mode), `opq set` checks existing metadata without reading the secret value and prints a
  stderr notice when overwriting an existing secret, replacing a TTL, or reviving a
  `REVOKED` / `UPDATE-PENDING` entry.
- **Policy reset and interrupted updates:** A plain `set` with neither `--ttl` nor
  `--keep-ttl` clears any prior policy on the name, including a revoked tombstone. An
  interrupted or failed update remains blocked as `UPDATE-PENDING`; retry `set` with the
  intended value/policy or explicitly `delete` the item.

## `opq list`

```sh
opq list [--long|-l] [--json] [--status all|active|expired|revoked|pending]
```

Prints stored secret names and policy state, never values. Internal `meta/` items appear
as status on the parent name, not as separate entries. Possible annotations:
`expires <ts>` (with relative remaining time on TTY), `EXPIRED`, `REVOKED`,
`UPDATE-PENDING`, and `meta-error` for an unreadable policy item.

| Flag | Behavior |
| --- | --- |
| `--long`, `-l` | Include `Status`, `CreatedAt`, and `ExpiresAt` / `RevokedAt` from policy metadata (never reads values). |
| `--json` | Emit a structured JSON array of secret metadata (never values). |
| `--status <state>` | Filter output: `all` (default), `active`, `expired`, `revoked`, or `pending`. |

On a TTY (default mode without `--json`), columns are aligned with relative expiry times
(for example `expires in 4h (2026-06-14 12:00 UTC)`) and subtle ANSI emphasis respecting
`NO_COLOR`; if zero secrets match, a helpful message is printed to stderr. When stdout is
not a TTY (piped/redirected) in default mode, output preserves the `<name>` /
`<name>\t<status>` format for script compatibility.

## `opq info`

```sh
opq info <name> [--json]
```

Inspects metadata for a single secret without ever reading its plaintext value. Displays
the secret `name`, `backend`, `status` (`active`, `expires ...`, `EXPIRED`, `REVOKED`,
`UPDATE-PENDING`, or `meta-error`), `created_at`, `expires_at` (with human-friendly
remaining or elapsed time), and `revoked_at`. Pass `--json` for machine-readable output.

Returns a clear error pointing to `opq list` if neither a secret key nor companion
metadata exists for `<name>`.

## `opq get`

```sh
OPQ_I_AM_HUMAN=1 opq get <name> --plaintext
```

The only way to read a plaintext value, gated so an automated or AI caller cannot use
it. Running `opq get <name>` without `--plaintext` recommends `opq exec` and prints the
exact human invocation above so operators do not hit a multi-step error loop.

It refuses unless all three hold:

1. stdout is a real TTY, so `opq get x | cat`, `> file`, and command substitution are
   blocked,
2. `OPQ_I_AM_HUMAN=1` is set inline on the command, and
3. you retype the secret's name on the controlling terminal (`/dev/tty`) when prompted.

Failing the gate writes a `denied` audit entry and aborts before any keyring access.

## `opq exec`

```sh
opq exec -e VAR[=name] [-e VAR2[=name2] ...] [--sandbox none|net|full] [--no-redact] -- cmd [args...]
```

Runs `cmd` with the named secrets injected as environment variables. Subprocess
stdout/stderr is redacted by default: every occurrence of every injected value, and its
base64/hex forms, is replaced with `[REDACTED:VAR]`.

- `--env` / `-e`: Accepts either `VAR=name` (maps env var `VAR` to stored secret `name`)
  or the shorthand `VAR` (maps `VAR=VAR`). Env-var names are capped at 256 bytes and
  checked against the [Environment Deny-List](./env-deny-list.md) (`LD_PRELOAD`, `PATH`,
  `BASH_ENV`, and so on).
- `--sandbox none|net|full`: Wraps the child in the OS-native sandbox (`bwrap` on Linux,
  `sandbox-exec`/Seatbelt on macOS) using the same profiles as the
  [MCP tool](../tutorials/sandbox-and-hardening.md#isolation-profiles). Defaults to
  `none` on the CLI.
- `--no-redact`: Disables redaction and is gated identically to `get --plaintext` (TTY +
  `OPQ_I_AM_HUMAN=1` + retype `no-redact` on the controlling terminal); the gate runs
  before any keyring access, and refusal writes a `denied` audit entry with
  `Message="no_redact_refused:<reason>"`.

`^C` is forwarded to the child, and so is a second `^C`, so you can escape a hung child.

## `opq delete`

```sh
opq delete <name>...
```

Accepts one or more secret names and removes each secret's value and any companion policy
item or tombstone (`opq delete old_key stale_key`).

## `opq revoke`

```sh
opq revoke <name>
```

Wipes the value from the keyring immediately and writes a revoked tombstone. Reads are
refused until the name is re-set or deleted. See
[TTL & Revocation](../tutorials/ttl-and-revocation.md).

## `opq prune`

```sh
opq prune [--dry-run] [--include-revoked]
```

Deletes every expired secret (value and policy). `--dry-run` lists what would be removed
without modifying the keyring. Pass `--include-revoked` (works with `--dry-run`) to also
clean up `REVOKED` tombstones.

`opq prune` completes the full sweep, reports each error, and returns a non-zero exit
status if any secret failed to prune so cron and systemd jobs catch failures.

## `opq audit`

```sh
opq audit [-n|--tail N] [--all] [--json] [--caller cli|mcp] [--action <action>] [--secret <name>]
```

Prints audit-log entries with full operator detail, unfiltered by the MCP AI allowlist.
Unlike the MCP `audit_tail` tool (which caps `n` at 200), the CLI imposes **no 200-entry
cap** — pass any positive `-n` / `--tail` or use `--all` to read every available entry
across the active log and one historical rotation (`audit.log.1`).

| Flag | Behavior |
| --- | --- |
| `-n`, `--tail N` | Show the last `N` matching entries across active + rotated log. |
| `--all` | Show all available matching entries across active + rotated log. |
| `--json` | Emit raw JSONL even when stdout is a TTY. |
| `--caller cli\|mcp` | Filter by caller before applying `--tail`. |
| `--action <action>` | Filter by audit action (e.g. `denied`, `mcp_run`, `set`) before applying `--tail`. |
| `--secret <name>` | Filter by secret name (matches `secret_name` or `secret_names`) before applying `--tail`. |

Filters run **before** taking the trailing `N` entries, so `opq audit -n 20 --action denied`
returns the last 20 denied events. On a TTY (unless `--json` is set), entries render as an
aligned table (`TIME`, `CALLER`, `ACTION`, `SECRET`, `DETAIL`) with subtle emphasis on
`denied`, `redaction_disabled`, and `network_allowed` (respecting `NO_COLOR`). On pipes
or with `--json`, `opq audit` emits raw JSONL. See the [Audit Log reference](./audit-log.md).

## `opq doctor`

```sh
opq doctor [--json]
```

Runs a read-only diagnostic health check of the `opq` runtime environment and reports
`OK`, `WARN`, or `FAIL` for each subsystem (never reads secret values):

1. **Binary & platform:** resolved `opq` version, OS, and architecture.
2. **Keyring backend:** opens the default backend and lists key counts, with OS-specific
   remediation if locked or missing CGO.
3. **Subprocess sandbox:** runs the OS sandbox availability probe (`bwrap` on Linux,
   `sandbox-exec`/Seatbelt on macOS).
4. **Audit log health:** verifies directory permissions (`0700`), symlink safety,
   `audit.log` mode (`0600` if present; reports `OK (not created yet)` on a fresh
   install), and size relative to the 10 MiB rotation threshold.
5. **Policy & metadata health:** verifies `policy.lock` directory permissions and counts
   `UPDATE-PENDING`, `meta-error`, `EXPIRED`, and `REVOKED` entries with exact recovery
   commands (`opq set`, `opq delete`, `opq prune`).

Pass `--json` for structured output. Exits `1` if any critical check has status `FAIL`;
`WARN` items exit `0`.

## `opq migrate`

```sh
opq migrate [--dry-run] [--overwrite] [--delete-legacy]
```

macOS-only migration helper for moving secrets created by earlier releases (which stored
one Keychain item per secret under service `opq`) into the AES-256-GCM encrypted local
vault (`~/.local/share/opq/vault.enc`, keyed by a single open-ACL master key in Keychain).
Values, TTLs, `REVOKED` tombstones, and `UPDATE-PENDING` markers are preserved atomically
under `policy.lock`.

| Flag | Behavior |
| --- | --- |
| `--dry-run` | Preview which legacy Keychain items would be migrated or skipped using attribute-only listing (never reads secret values or prompts for passwords). |
| `--overwrite` | Replace secrets that already exist in the vault (default skips existing entries so re-runs are idempotent). |
| `--delete-legacy` | Remove each migrated secret and its metadata from the legacy Keychain after verifying it is stored in the vault. |

By default, `opq migrate` keeps legacy Keychain entries intact as a backup. Verify with
`opq list` and `opq doctor`, then run `opq migrate --delete-legacy` to remove them. On
Linux and other platforms, `opq migrate` is a no-op.

## `opq completion`

```sh
opq completion <bash|zsh|fish>
```

Prints a self-contained completion script for `bash`, `zsh`, or `fish` covering all
subcommands, flags, enum values (`--sandbox`, `--caller`, `--status`), and dynamic
secret-name completion for `get`, `info`, `delete`, `revoke`, and `set` via `opq list`
(never reads secret values). See [Shell completion](../getting-started/installation.md#shell-completion)
for setup instructions.

## `opq mcp`

```sh
opq mcp
```

Runs the MCP server over stdio. Stops if the OS sandbox is unavailable (on Linux,
`bwrap` missing or the namespace probe fails; on macOS, `sandbox-exec` unavailable). See
[MCP Tools](./mcp-tools.md).
