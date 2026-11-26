# opq

[![Install with Homebrew](https://img.shields.io/badge/Homebrew-brew%20install%20alexrios%2Ftap%2Fopq-FBB040?logo=homebrew&logoColor=white)](https://github.com/alexrios/homebrew-tap)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> **Status:** v1.5.0. Linux (Secret Service) and macOS (encrypted local vault + Keychain master key) supported.

An **AI-safe secrets CLI**: stores secrets in your OS keyring and lets programs (and AI agents) use them with output redaction against accidental disclosure. Invoked as `opq`.

```sh
opq exec --env OPENAI_API_KEY=openai_key -- ./my-client  # ok: secret injected, output redacted
opq get  openai_key | cat                                # blocked: never plaintext to a pipe
opq mcp                                                  # MCP server over stdio for AI agents
```

The agent calls `opq exec` (or the `run_with_secrets` MCP tool); `opq` injects the secret as an env var into the child, scans the child's output, and replaces the value with `[REDACTED:VAR]` before it reaches the agent. Raw and common base64/hex forms are redacted. A malicious consuming program can still encode secrets in output or exfiltrate them when network access is granted. For untrusted agents, use the [operator-owned policy proxy example](examples/policy-proxy/README.md) to expose fixed operations instead of arbitrary commands. There is deliberately **no** `get_secret_value` MCP tool.

## Install

```sh
brew install alexrios/tap/opq               # Homebrew (macOS & Linux)
go install github.com/alexrios/opq@latest   # or via the Go toolchain
```

Verify your keyring, sandbox, audit log, and policy state in one step:

```sh
opq doctor
```

Keyring backend by platform:

- **Linux:** an unlocked Secret Service session (gnome-keyring / KWallet / KeePassXC).
- **macOS:** an AES-256-GCM encrypted local vault (`~/.local/share/opq/vault.enc`, mode `0600`) whose single master key lives in the login Keychain (`opq-vault` / `master-key`, open app ACL so upgrades and rebuilds never trigger repeated Keychain password prompts). Run `opq migrate` if upgrading from an earlier release that stored secrets directly in Keychain. The binary must be built with CGO enabled (the default for `go install` on macOS; needs the Xcode Command Line Tools) so it can link the Security framework.

The MCP sandbox is implemented on both Linux (via **bubblewrap**, `bwrap`) and macOS (via `sandbox-exec` / Seatbelt, built in); other platforms accept only `--sandbox=none`.

## Quick Start

Try it offline in 30 seconds — no API key or network required:

```sh
# 1. Store a secret (reads from stdin or a hidden prompt, never argv)
printf 'super-secret-value' | opq set demo_key

# 2. List stored names (values are never printed)
opq list

# 3. Inject as an env var and watch output redaction work
opq exec -e API=demo_key -- sh -c 'echo "leaked: $API"'
# → leaked: [REDACTED:API]

# 4. Inspect the audit log and clean up
opq audit --tail 5
opq delete demo_key
```

For real credentials, prefer tools and SDKs that read directly from environment variables (`opq exec -e GH_TOKEN=gh_token -- gh api /user`), or pass headers over stdin (such as `curl -K -`) so secret values never expand into command arguments visible in `ps`.

## MCP Setup

Register `opq mcp` as a stdio MCP server in your AI client.

**Claude Code:**

```sh
claude mcp add opq -- opq mcp
```

**Claude Desktop, Cursor, VS Code, and other MCP clients (`mcpServers` JSON):**

```json
{
  "mcpServers": {
    "opq": {
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

GUI clients often start with a minimal `PATH`; if the client cannot find `opq`, set `"command"` to the full path from `which opq` (for example `/opt/homebrew/bin/opq`). See the [MCP setup tutorial](https://alexrios.github.io/opq/tutorials/mcp-claude-code.html) for per-client config file paths and VS Code's `.vscode/mcp.json` format.

## Claude Code skill

This repo ships a [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills) ([`opq.skill`](opq.skill)) that teaches an agent to install `opq`, register the MCP server, and use secrets safely. Drop it into any agent harness:

```sh
unzip opq.skill -d ~/.claude/skills/   # → ~/.claude/skills/opq/SKILL.md
```

It activates whenever a task needs a credential (e.g. calling an authenticated API) and guides the agent through name-based credential use with output redaction.

## Documentation

The full documentation lives in the mdbook, published at **<https://alexrios.github.io/opq/>** (source under [`docs/`](docs/src/SUMMARY.md)): getting started, tutorials, the complete CLI/MCP reference, and the detailed security model. Build and read it locally:

```sh
mise run docs        # build to docs/book/
mise run docs:serve  # live-reload preview at http://localhost:3000
```

## Upgrade to v1.5.0 (macOS)

macOS now stores secrets in an AES-256-GCM encrypted local vault (`~/.local/share/opq/vault.enc`) keyed by a single open-ACL master key in the login Keychain (`opq-vault`), eliminating per-secret password prompts after upgrades and rebuilds. Stop running `opq mcp` servers, upgrade, run `opq migrate` to copy existing Keychain secrets (with TTL and revocation metadata preserved), verify with `opq list` and `opq doctor`, and then optionally run `opq migrate --delete-legacy`. See the [release and upgrade notes](https://alexrios.github.io/opq/appendix/version-history.html#v150-current).

## Upgrade to v1.3.0

Stop existing `opq` MCP, policy-proxy, and `exec` processes before upgrading, then restart them with the new binary. Older binaries do not understand interrupted policy updates and must not access the same keyring concurrently. See the [release and upgrade notes](https://alexrios.github.io/opq/appendix/version-history.html#v130).

## Development

```sh
mise run check       # vet + test + build
mise run vulncheck   # govulncheck ./...
```

## License

[GNU AGPL-3.0](LICENSE).
