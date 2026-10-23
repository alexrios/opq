# opq

[![Install with Homebrew](https://img.shields.io/badge/Homebrew-brew%20install%20alexrios%2Ftap%2Fopq-FBB040?logo=homebrew&logoColor=white)](https://github.com/alexrios/homebrew-tap)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> **Status:** v1.3.0. Linux (Secret Service) and macOS (Keychain) supported.

An **AI-safe secrets CLI**: stores secrets in your OS keyring and lets programs (and AI agents) use them with output redaction against accidental disclosure. Invoked as `opq`.

```sh
opq exec --env OPENAI_API_KEY=openai_key -- curl ...   # ok: secret injected, output redacted
opq get  openai_key | cat                              # blocked: never plaintext to a pipe
opq mcp                                                # MCP server over stdio for AI agents
```

The agent calls `opq exec` (or the `run_with_secrets` MCP tool); `opq` injects the secret as an env var into the child, scans the child's output, and replaces the value with `[REDACTED:VAR]` before it reaches the agent. Raw and common base64/hex forms are redacted. A malicious consuming program can still encode secrets in output or exfiltrate them when network access is granted. For untrusted agents, use the [operator-owned policy proxy example](examples/policy-proxy/README.md) to expose fixed operations instead of arbitrary commands. There is deliberately **no** `get_secret_value` MCP tool.

## Upgrade to v1.3.0

Stop existing opq MCP, proxy, and exec processes before upgrading, then restart them
with the new binary. Older binaries do not understand interrupted policy updates and
must not access the same keyring concurrently. See the [release and upgrade notes](https://alexrios.github.io/opq/appendix/version-history.html#v130-current).

## Install

```sh
brew install alexrios/tap/opq               # Homebrew (macOS & Linux)
go install github.com/alexrios/opq@latest   # or via the Go toolchain
```

Keyring backend by platform:

- **Linux:** an unlocked Secret Service session (gnome-keyring / KWallet / KeePassXC).
- **macOS:** the login Keychain (no extra install). The binary must be built with CGO enabled (the default for `go install` on macOS; needs the Xcode Command Line Tools) so it can link the Security framework.

The MCP sandbox is implemented on both Linux (via **bubblewrap**, `bwrap`) and macOS (via `sandbox-exec` / Seatbelt, built in); other platforms accept only `--sandbox=none`.

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

## Development

```sh
mise run check       # vet + test + build
mise run vulncheck   # govulncheck ./...
```

## License

[GNU AGPL-3.0](LICENSE).
