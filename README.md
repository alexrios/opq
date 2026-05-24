# opaque

> **Status:** v0.1.0 — alpha. Linux only for now; macOS Keychain backend planned for v1.1.

An **AI-safe secrets CLI** — stores secrets in your OS keyring and lets programs (and AI agents) use them without ever exposing plaintext. Invoked as `opq`.

```
$ opq exec --env OPENAI_API_KEY=openai_key -- curl ... # ok
$ opq get  openai_key | cat                            # blocked
$ opq mcp                                              # MCP server over stdio
```

## Why

When you let an AI agent run shell commands, the agent shouldn't see your API keys. But the **subprocess** the agent spawns still needs them. `opaque` sits between the two:

- The agent calls `opq exec --env VAR=secret_name -- ...` (or the `run_with_secrets` MCP tool).
- `opq` looks up the secret in your keyring and injects it as an environment variable into the child process.
- The child uses the secret normally. Anything the child accidentally writes to stdout/stderr is scanned, and the secret value is replaced with `[REDACTED:VAR]` before reaching the agent.
- The agent never receives the plaintext, only the redacted output.

## Threat model

**In scope:**

- AI reading plaintext from stdout, error messages, or argv.
- AI piping `opq get` to capture values (refused unless stdout is a TTY).
- Subprocesses accidentally echoing secrets (output redaction).
- Shell-history exposure (no secret ever appears in argv).
- Process-list exposure (`ps auxe`) — secrets enter child via `exec` env, not via shell interpolation.
- Memory swap-out of secret pages (mlocked buffers via `memguard`).

**Out of scope (v1):**

- Root / kernel attacker.
- Side channels in the legitimate consuming subprocess.
- A malicious subprocess that intentionally exfiltrates the secret it was given.
- Tamper-evident audit log (file mode 0600 only; not cryptographically signed).

## Install

```
go install github.com/alexrios/opaque@latest
```

The installed binary is named `opq`.

Requirements:

- Linux with an unlocked Secret Service session (gnome-keyring, KWallet, or KeePassXC).
- Go 1.26+ to build from source.

## Quick start

```sh
# Store a secret. Value is read from stdin or prompted on a TTY — never on argv.
printf 'sk-...' | opq set openai_api_key

# List names (never values).
opq list

# Use the secret without ever seeing it.
opq exec --env OPENAI_API_KEY=openai_api_key -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# What's in the audit log?
opq audit --tail 10
```

## CLI

| Command | Behavior |
| --- | --- |
| `opq set <name>` | Read value from stdin (or hidden TTY prompt). Never accepts values on argv. |
| `opq list` | Print stored secret names. |
| `opq delete <name>` | Remove a secret. |
| `opq get <name> --plaintext` | Print value to stdout. **Refuses** to run unless stdout is a TTY. |
| `opq exec --env VAR=name [...] -- cmd args` | Run `cmd` with named secrets injected as env vars. Subprocess output is redacted. |
| `opq audit [--tail N]` | Show audit-log entries. |
| `opq mcp` | Run as a Model Context Protocol server over stdio. |

## MCP server

Add to your MCP-aware client (Claude Code, etc.):

```jsonc
{
  "mcpServers": {
    "opq": {
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

The server exposes three tools:

- `list_secrets()` — returns secret names only.
- `run_with_secrets({ command, args, env: { VAR: secret_name } })` — runs the command with secrets injected; returns redacted stdout/stderr + exit code.
- `audit_tail({ n })` — recent audit entries.

There is **no** `get_secret_value` tool by design. AIs can use secrets, not read them.

## Backends

v1 ships with the Secret Service backend (libsecret over D-Bus) for Linux. The `Backend` interface in `backend.go` is shaped so additional backends drop in without touching anything else:

- macOS Keychain (planned, v1.1).
- Proton Pass (planned, v2).
- `pass` / file-based / KWallet are already reachable via the underlying `99designs/keyring` library; flip them on by editing `AllowedBackends` in `OpenDefaultBackend`.

## Audit log

`${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log`, mode 0600. One JSON object per line. Actions: `set`, `get`, `delete`, `list`, `exec_inject`, `mcp_run`, `redaction_disabled`, `denied`.

Example entry:

```json
{"ts":"2026-05-24T15:50:17.189Z","action":"exec_inject","secret_name":"openai_api_key","caller":"cli","pid":50770,"ppid":50701}
```

`caller` is `cli` for direct CLI invocations and `mcp` when the request came through the MCP server, so you can distinguish AI-driven access from human-driven access at a glance.

## Memory hygiene

Secret bytes flow through `memguard.LockedBuffer`s — mlocked pages, guard canaries, zeroed on destroy. The default build is enough for the threat model above.

For an extra hardening layer that erases transient stack + heap copies between the locked buffer and the child env, build with:

```sh
GOEXPERIMENT=runtimesecret go build -tags runtimesecret .
```

This wraps the env-construction code path in `runtime/secret.Do(...)` (Go 1.26.3+, experimental). Linux/amd64 and linux/arm64 only.

## Development

```sh
go test ./...
go vet ./...
go build .
```

End-to-end smoke tests require an unlocked Secret Service session on the host.
