# Installation

## Install with Homebrew

```sh
brew install alexrios/tap/opq
```

Installs a prebuilt binary from the
[`alexrios/homebrew-tap`](https://github.com/alexrios/homebrew-tap) tap, on macOS (Apple
Silicon or Intel) and Linux. No Go toolchain or CGO setup required.

## Install with `go install`

```sh
go install github.com/alexrios/opq@latest
```

The installed binary is named `opq` (Go names the binary after the last element of the
module path). Put your `$GOBIN` (or `$GOPATH/bin`) on `$PATH`.

## Build from source

```sh
git clone https://github.com/alexrios/opq
cd opq
go build -o opq .          # or: mise run build  → dist/opq
```

## Verifying the install

Run `opq doctor` to verify the binary, keyring backend, OS sandbox, audit log directory,
and policy state in a single read-only check (it never reads secret values):

```sh
opq doctor
```

Use `opq doctor --json` for machine-readable output in CI or provisioning scripts.
`doctor` exits `0` when all critical checks pass (`OK` or `WARN`) and `1` if any
critical check reports `FAIL`.

You can also inspect the version and binary path directly:

```sh
opq --version
which opq          # confirm the right binary is on PATH
```

If `opq doctor` reports a D-Bus or Secret Service error on Linux, your keyring session is
not unlocked. On a desktop, log into a graphical session so the keyring unlocks
automatically. On a headless host, container, or WSL there is usually no session keyring
yet: start one with `gnome-keyring-daemon --unlock` (or wrap the command in
`dbus-run-session -- opq ...`), or install KeePassXC and enable its Secret Service
integration. `opq` needs an unlocked libsecret provider and will not fall back to a
plaintext file.

## Shell completion

Generate completion scripts for `bash`, `zsh`, or `fish` with `opq completion`. Tab
completion covers all subcommands, flags, and dynamic secret names (fetched via
`opq list`, so values are never read):

```sh
# Bash (~/.bashrc)
eval "$(opq completion bash)"

# Zsh (~/.zshrc)
eval "$(opq completion zsh)"

# Fish
opq completion fish > ~/.config/fish/completions/opq.fish
```

## Install the Claude Code skill

For agent-driven workflows, this repo ships a
[Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills) that teaches an
agent to install `opq`, register the MCP server, and reference existing credentials by
name with output redaction. The skill is bundled as
[`opq.skill`](https://github.com/alexrios/opq/blob/main/opq.skill) (a ZIP); install it
into any harness by unpacking it under your skills directory:

```sh
unzip opq.skill -d ~/.claude/skills/   # → ~/.claude/skills/opq/SKILL.md
```

The skill activates automatically whenever a task needs a credential (for example,
calling an authenticated API) and walks the agent through the name-based credential workflow:
`run_with_secrets` over MCP and `opq exec` on the CLI. It complements the binary install
above; the agent still needs the `opq` binary on `PATH` (the skill covers installing
it).

## Requirements

`opq` runs on Linux and macOS. On a standard desktop session of either the requirements
below are already met, and `opq` works out of the box. They matter mainly for headless
servers, containers, WSL, and locked-down hosts.

### Linux

| Requirement | Why | Notes |
| --- | --- | --- |
| An unlocked Secret Service session | Where secrets are stored. | gnome-keyring, KWallet, or KeePassXC (anything that speaks libsecret over D-Bus). |
| bubblewrap (`bwrap`) ≥ 0.5.0 | The MCP subprocess sandbox and `opq exec --sandbox`. | `apt install bubblewrap` / `dnf install bubblewrap` / `pacman -S bubblewrap`. `opq mcp` will not start without it. |
| Unprivileged user namespaces | bubblewrap needs them to build the sandbox. | Enabled by default on most distros. |

### macOS

| Requirement | Why | Notes |
| --- | --- | --- |
| The login Keychain | Protects the vault master key. | `opq` encrypts secrets and policy metadata in `~/.local/share/opq/vault.enc` (AES-256-GCM, mode `0600`) using a single 256-bit master key stored in the login Keychain under service `opq-vault` (`master-key`) with an open application ACL. The keychain must be unlocked (it is, while you are logged in). |
| A CGO-enabled build | The Keychain master-key store links the Security framework via cgo. | `go install` enables CGO by default on macOS; you need the Xcode Command Line Tools (`xcode-select --install`). A `CGO_ENABLED=0` build fails at first keyring access with an actionable error. |
| `sandbox-exec` | The MCP subprocess sandbox and `opq exec --sandbox`. | Ships with macOS at `/usr/bin/sandbox-exec`; no install needed. |

Because the single vault master key uses an open application ACL (matching Linux Secret
Service's session model), upgrades via Homebrew and local rebuilds do not trigger repeated
Keychain password prompts. If you previously stored secrets with an older release of `opq`
(which saved one Keychain item per secret under service `opq`), run `opq migrate` once to
move them—along with their TTL and revocation metadata—into the encrypted vault, then
verify with `opq doctor` and optionally clean up with `opq migrate --delete-legacy`.

## Troubleshooting: the bubblewrap startup probe

Most desktop users never see this section. It applies only when `opq mcp` refuses to
start on a hardened or headless host.

`opq mcp` runs a no-op namespace probe at startup (`bwrap --unshare-net --unshare-pid
-- true`). If AppArmor (Ubuntu 23.10+ ships a profile on `bwrap`), seccomp, or a kernel
without `CONFIG_USER_NS` blocks unprivileged namespace creation, the server stops with
a clear error instead of failing at the first tool call. `opq doctor` runs the same
sandbox probe so you can verify fixes interactively.

If the probe fails on Ubuntu 23.10+, you likely need to allow `bwrap` in AppArmor or
enable unprivileged user namespaces:

```sh
sysctl kernel.unprivileged_userns_clone 2>/dev/null
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null
```

## Upgrading from an older release

Before upgrading to v1.3.0, stop existing MCP servers, policy proxies, and secret-backed
exec processes, then restart them with the new binary. Existing credentials remain in
the OS keyring. Older clients must not run concurrently against the same keyring; see
the [release and upgrade notes](../appendix/version-history.md#upgrade-notes) for
pending-update recovery and MCP output/limit changes.

Next: [Quick Start](./quick-start.md).
