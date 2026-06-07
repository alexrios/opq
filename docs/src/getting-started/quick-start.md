# Quick Start

Four commands, assuming `opq` is [installed](./installation.md) and your keyring
session is unlocked.

```sh
# 1. Store a secret under the name "openai_key"
printf 'sk-...' | opq set openai_key

# 2. List names
opq list

# 3. Use it: inject the stored "openai_key" as the env var OPENAI_API_KEY
opq exec --env OPENAI_API_KEY=openai_key -- \
  sh -c 'curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"'

# 4. Review what happened
opq audit --tail 10
```

`--env OPENAI_API_KEY=openai_key` maps the environment variable `OPENAI_API_KEY` (what
the subprocess reads) to the secret stored as `openai_key` (the left side is the env var,
the right side is the opq name). `set` reads the value from stdin (never argv, so it
stays out of shell history and `ps` output). `list` prints names only. `exec` resolves
`openai_key`, injects its value as `OPENAI_API_KEY`, and scans the output; if the value
(or its base64/hex form) had appeared, it would come back as `[REDACTED:OPENAI_API_KEY]`
(the token uses the env var name). `audit` shows the `set` and `exec_inject` entries.

## Try the redaction

Ask a subprocess to print the secret and watch it come back redacted:

```sh
printf 'super-secret-value' | opq set demo_key
opq exec --env API=demo_key -- sh -c 'echo "leaked: $API"'
# → leaked: [REDACTED:API]
opq delete demo_key
```

The subprocess received `super-secret-value` in `$API`; it cannot print it back in the
clear.

## Next

- [CLI Basics](../tutorials/cli-basics.md) walks the same commands in more depth.
- [opq + Claude Code](../tutorials/mcp-claude-code.md) wires `opq` into an AI agent.
- [CLI Commands](../reference/cli-commands.md) is the full command surface.
