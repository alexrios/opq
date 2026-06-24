# opq

> **Status:** v1.1.6. Linux only for now. Backends: OS keyring (default), HashiCorp Vault, and Proton Pass (read-only); macOS Keychain planned for v1.2.

An **AI-safe secrets CLI**: stores secrets in your OS keyring and lets programs (and AI agents) use them without ever exposing plaintext. Invoked as `opq`.

```sh
opq exec --env OPENAI_API_KEY=openai_key -- curl ...   # ok: secret injected, output redacted
opq get  openai_key | cat                              # blocked: never plaintext to a pipe
opq mcp                                                # MCP server over stdio for AI agents
```

The agent calls `opq exec` (or the `run_with_secrets` MCP tool); `opq` injects the secret as an env var into the child, scans the child's output, and replaces the value with `[REDACTED:VAR]` before it reaches the agent. The agent never sees the plaintext. There is deliberately **no** `get_secret_value` MCP tool.

## Install

```sh
go install github.com/alexrios/opq@latest
```

Requires Linux with an unlocked Secret Service session (gnome-keyring / KWallet / KeePassXC) and **bubblewrap** (`bwrap`) for the MCP sandbox.

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
