# CLI Basics

The everyday loop: store a secret, use it, check the audit trail, clean up. Every
command here is safe to run with an unlocked keyring.

## 1. Store a secret

Values are never read from argv. `opq set` reads from stdin, or prompts on the hidden
TTY if stdin is a terminal.

```sh
# From stdin (pipe, here-string, or file):
printf 'sk-live-abc123' | opq set stripe_secret_key

# Interactive hidden prompt (nothing echoes as you type):
opq set stripe_secret_key
# Enter value for 'stripe_secret_key': ********
```

The interactive prompt strips surrounding whitespace and bracketed-paste markers, so
pasting from a web page or a `.env` line works. The piped path stores bytes verbatim; a
value that needs leading or trailing whitespace must come in over stdin, not the
prompt.

Secret names match `[A-Za-z0-9_.-]{1,128}`: no slashes, no spaces.

## 2. List your secrets

```sh
opq list
```

`list` prints names only, never values, annotated with policy state where one applies:

```text
stripe_secret_key
openai_key      expires 2026-06-14T12:00:00Z
old_token           REVOKED
stale_token         EXPIRED
```

## 3. Use a secret in a command

`opq exec` injects one or more named secrets as environment variables and redacts the
child's output. Everything after `--` is the command and its arguments; the values
exist only in the child's environment and never reach your shell's argv.

Start local, with no network, to see redaction directly:

```sh
opq exec --env API=stripe_secret_key -- sh -c 'echo "value is $API"'
# → value is [REDACTED:API]
```

The same shape works against a real service:

```sh
opq exec --env STRIPE_KEY=stripe_secret_key -- \
  sh -c 'curl -s https://api.stripe.com/v1/charges -u "$STRIPE_KEY:"'
```

Inject several at once:

```sh
opq exec \
  --env STRIPE_KEY=stripe_secret_key \
  --env OPENAI_KEY=openai_key \
  -- ./my-script.sh
```

The redactor also catches base64 and hex forms, so a subprocess that pipes the secret
through `base64` or `xxd` does not leak it by accident. See
[The Redactor](../security/redactor.md) for what is and is not covered.

## 4. Inspect the audit log

```sh
opq audit --tail 10
```

```json
{"ts":"2026-06-07T12:00:00.000Z","action":"set","secret_name":"stripe_secret_key","caller":"cli","pid":1234}
{"ts":"2026-06-07T12:00:05.000Z","action":"exec_inject","secret_name":"stripe_secret_key","caller":"cli","pid":1240}
```

`caller` is `cli` for direct CLI use and `mcp` when the request came through the MCP
server, so human and AI access are distinguishable. See the
[Audit Log reference](../reference/audit-log.md) for the full schema.

## 5. Clean up

```sh
opq delete stripe_secret_key
```

`delete` removes the value and any TTL or revocation record.

## Reading a value

Sometimes a human needs to see a value. `opq get --plaintext` does that, gated so an
automated caller cannot use it:

```sh
opq get stripe_secret_key --plaintext
```

It refuses unless all three hold:

1. stdout is a real TTY, so `opq get ... | cat` and redirects to a file are blocked,
2. `OPQ_I_AM_HUMAN=1` is set inline on the command, and
3. you retype the secret's name on the controlling terminal when prompted.

This is the same gate that protects `exec --no-redact`. See
[CLI Commands](../reference/cli-commands.md#opq-get).

## Next

- [TTL & Revocation](./ttl-and-revocation.md) bounds how long a secret stays usable.
- [opq + Claude Code](./mcp-claude-code.md) hands secrets to an AI agent.
