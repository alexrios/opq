# CLI Commands

The complete `opq` command surface. Each command records an entry in the
[audit log](./audit-log.md).

| Command | Behavior |
| --- | --- |
| `opq set <name> [--ttl 24h\|7d\|2w]` | Read value from stdin (or hidden TTY prompt). Never accepts values on argv. `--ttl` sets a time-to-live after which reads are refused; omit for no expiry. |
| `opq list` | Print stored secret names, annotated with `expires <ts>` / `EXPIRED` / `REVOKED` where a policy applies. |
| `opq get <name> --plaintext` | Print value to stdout. Refuses unless stdout is a TTY (plus the human gate, below). |
| `opq exec --env VAR=name [...] -- cmd args` | Run `cmd` with named secrets injected as env vars. Output redacted by default. |
| `opq delete <name>` | Remove a secret and any TTL/revocation record. |
| `opq revoke <name>` | Wipe a secret's value immediately and leave a revoked tombstone. |
| `opq prune [--dry-run]` | Delete every expired secret (value + policy). `--dry-run` previews. |
| `opq audit [--tail N]` | Show audit-log entries. |
| `opq mcp` | Run as a Model Context Protocol server over stdio. |

## Global flags

`--backend keyring|vault|proton-pass` (or `$OPQ_BACKEND`; the flag wins) selects the secret
store for any command. It defaults to `keyring`. An unknown value is rejected. See
[Backends](../appendix/backends.md).

## `opq set`

```sh
opq set <name> [--ttl <duration>]
```

Reads the value from stdin if stdin is a pipe or file, or prompts on the hidden TTY if
stdin is a terminal. Values are never read from argv.

Names match `[A-Za-z0-9_.-]{1,128}`: no slashes (the `/` namespace is reserved for
internal policy items), no spaces. `--ttl` accepts `90m`, `24h`, `7d`, `2w`, and so on;
it writes a companion policy item and fails closed, rolling back the value if the policy
write fails. The interactive prompt disables bracketed-paste mode and trims surrounding
whitespace; the piped path stores bytes verbatim, so supply whitespace-significant
values over stdin. A plain `set` with no `--ttl` clears any prior policy on the name,
including a revoked tombstone. NUL-bearing values are rejected, since `os/exec` cannot
pass them as env entries anyway.

## `opq list`

```sh
opq list
```

Prints names only, never values. Annotations: `expires <ts>` for a live TTL, `EXPIRED`
past it, `REVOKED` for a tombstone, `meta-error` for an unreadable policy item.
Internal `meta/` items appear as status on the parent name, not as separate entries.

## `opq get`

```sh
OPQ_I_AM_HUMAN=1 opq get <name> --plaintext
```

The only way to read a plaintext value, gated so an automated or AI caller cannot use
it. It refuses unless all three hold:

1. stdout is a real TTY, so `opq get x | cat`, `> file`, and command substitution are
   blocked,
2. `OPQ_I_AM_HUMAN=1` is set inline on the command, and
3. you retype the secret's name on the controlling terminal (`/dev/tty`) when prompted.

Failing the gate writes a `denied` audit entry and aborts before any keyring access.

## `opq exec`

```sh
opq exec --env VAR=name [--env VAR2=name2 ...] [--sandbox net|full] [--no-redact] -- cmd [args...]
```

Runs `cmd` with the named secrets injected as environment variables. Subprocess
stdout/stderr is redacted by default: every occurrence of every injected value, and its
base64/hex forms, is replaced with `[REDACTED:VAR]`.

`--env VAR=name` maps an env var name to a stored secret name. Env-var names are capped
at 256 bytes and checked against the [deny-list](./env-deny-list.md) (`LD_PRELOAD`,
`PATH`, `BASH_ENV`, and so on). `--sandbox net|full` wraps the child in a bubblewrap
sandbox using the same profiles as the
[MCP tool](../tutorials/sandbox-and-hardening.md#isolation-profiles). `--no-redact`
disables redaction and is gated identically to `get --plaintext` (TTY +
`OPQ_I_AM_HUMAN=1` + retype `no-redact` on the controlling terminal); the gate runs
before any keyring access, and refusal writes a `denied` audit entry with
`Message="no_redact_refused:<reason>"`.

`^C` is forwarded to the child, and so is a second `^C`, so you can escape a hung child.

## `opq delete`

```sh
opq delete <name>
```

Removes the value and any companion policy item.

## `opq revoke`

```sh
opq revoke <name>
```

Wipes the value from the keyring immediately and writes a revoked tombstone. Reads are
refused until the name is re-set or deleted. See
[TTL & Revocation](../tutorials/ttl-and-revocation.md).

## `opq prune`

```sh
opq prune [--dry-run]
```

Deletes every expired secret (value and policy). `--dry-run` lists what would go
without deleting. Pair with cron or a systemd timer for automatic hygiene.

## `opq audit`

```sh
opq audit [--tail N]
```

Prints audit-log entries with full operator detail, unfiltered. `--tail N` shows the
last `N` and spans the active log and one historical rotation. See the
[Audit Log reference](./audit-log.md).

## `opq mcp`

```sh
opq mcp
```

Runs the MCP server over stdio. Stops if bubblewrap is missing or the namespace probe
fails. See [MCP Tools](./mcp-tools.md).
