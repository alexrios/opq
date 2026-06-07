# The Redactor

When a subprocess receives a secret and prints it, `opq` scans the output and replaces
the value with `[REDACTED:VAR]` before returning it. This catches a subprocess that
echoes a secret by accident. It does not stop a subprocess that deliberately encodes
the value in a form `opq` does not recognize (see
[Threat Model](./threat-model.md#out-of-scope-v1)).

The code is `RedactingWriter` in `redact.go`, an `io.Writer` that wraps the downstream
sink.

## Split writes

A subprocess can print a secret one byte at a time, or split it across two `Write`
calls. `RedactingWriter` keeps a holdover of `maxSecretLen - 1` bytes between writes,
so a value that straddles a write boundary is still matched.

## Overlapping secrets

If two stored secrets overlap — `ABC` and `BCD` are both registered and the subprocess
prints `ABCD` — both are redacted, producing `[REDACTED:S1][REDACTED:S2]`. `scan()`
uses two cursors: `i` advances one byte per iteration so every position is tested as a
possible secret start, and `emitUpTo` tracks how far the current match extends, so
bytes inside a match that do not begin a new secret are suppressed rather than emitted.

## Encoded forms

A subprocess that pipes the secret through `base64` or `xxd` would slip past a
byte-exact matcher. `NewRedactingWriter` registers several encodings of each secret,
all mapped to the same `[REDACTED:NAME]` token:

| Form | Variants |
| --- | --- |
| Raw bytes | the value itself |
| Base64 | standard and URL-safe, padded and unpadded |
| Hex | lower- and upper-case |

Identical forms register once: a short secret whose standard and URL base64 match does
not register twice. Secrets shorter than 4 bytes (`encodingMinRawLen`) skip the encoded
forms, because their short encoded outputs match innocuous log text too often; the raw
form still registers.

URL percent-encoding and JSON-string escaping are not registered, since both are no-ops
for typical alphanumeric API keys. Ciphers (rot13, XOR, base32) and entropy heuristics
are not registered either: the first would grow the registered set without a clear
limit, and the second produces false positives on hashes, UUIDs, and tokens.

## Short-circuit on truncation

If the downstream sink reports that it has truncated — it implements
`truncatedReporter { Truncated() bool }`, currently only the MCP `cappedWriter` —
`RedactingWriter` switches to pass-through. Without this, an AI running a high-volume
producer like `yes` would spend the whole MCP timeout in `scan()` over bytes the 256
KiB cap discards anyway.

The check is a one-shot type assertion in `NewRedactingWriter`. An interposer placed
between the redactor and the capped writer has to proxy `Truncated()` or the
short-circuit stops working; a structural test guards this.

## Tests

`redact_test.go` covers byte-by-byte writes, split writes, overlapping and
self-overlapping secrets, and each encoded form. Changes to `scan()` or the form
expansion need to keep those passing.
