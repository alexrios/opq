# Design Decisions

Some of `opq`'s most consequential choices are absences and constraints: things
deliberately not built. This page records the reasoning so they are not "fixed" by a
well-meaning change.

## The security invariants

These hold because the value proposition collapses if any is violated. The codebase
enforces them with tests against unexported internals.

- No plaintext to stdout when stdout is not a TTY. Enforced in `cmd_get.go`, plus the
  `OPQ_I_AM_HUMAN=1` env gate and a `/dev/tty` retyped-name confirmation.
- No secret value on argv, ever. `set` reads from stdin or a hidden TTY prompt only.
- No MCP tool that returns a plaintext value. The absence of `get_secret_value` is the
  control.
- Every value read goes through `resolveSecret` (TTL/revocation enforcement); see
  [TTL Internals](./ttl-revocation.md).
- No injected env var on the loader deny-list; see
  [Environment Deny-List](../reference/env-deny-list.md).
- Subprocess output redacted by default; `--no-redact` is gated like `get --plaintext`.
- The redactor handles split writes, overlapping secrets, and encoded forms; see
  [The Redactor](./redactor.md).
- Secret values live in `memguard` buffers, never in a long-lived `string`, always with
  `defer buf.Destroy()`.
- Audit writes go through the flock pattern; audit `msg` never carries raw backend error
  text.
- The MCP sandbox masks the keyring, runtime sockets, and credential agents; see
  [The Sandbox](./sandbox.md).

## The absent get_secret_value MCP tool

The most important design decision is a tool that does not exist. An AI can use secrets
(`run_with_secrets`) and list names (`list_secrets`), but no API returns a value. Adding
one, even for debugging, would void the core property.

## The flat package layout

Every `.go` file lives in the repository root under one `package main`: no `internal/`
tree, no sub-packages. The reasons:

- The codebase is small (~4k non-test lines). Package boundaries earn their keep an order
  of magnitude larger, or when a second binary or external library boundary forces a seam;
  neither applies.
- The guarantees are enforced by tests against unexported internals
  (`filterAuditMessageForAI`, `resolveSecret`, `encodedSecretForms`, and so on). Splitting
  into packages would force exporting them, widening the API surface the project works to
  keep closed.
- A package boundary would not enforce any invariant that matters here. The invariants are
  semantic ("no plaintext to a non-TTY"), not structural; the compiler cannot check them
  across a package line. One concern per file, with its test beside it, keeps each contract
  auditable in one place.

Readability comes from file-name prefixes (`cmd_*.go`, `mcp_*.go`, `sandbox_*.go`) instead
of directories. The bar for a new package is a concrete forcing function: a second binary,
a publishable library boundary, or a file past ~2k lines.

## Features evaluated and declined

Considered and declined for v1; do not re-pitch without new information:

- Use-count limits: break the read-only read path (need a per-resolve write-back plus a
  cross-process counter lock). Cost outweighs value.
- Absolute `--expires-at`: sugar over `--ttl` unless mirroring an external token's own
  expiry, which is not a current workflow.
- Auto-destruction daemon: a cron/systemd `opq prune` recipe, not a resident daemon.
- Per-project allowlist / policy files: belong in a deployment-side
  [policy proxy](../tutorials/sandbox-and-hardening.md#the-policy-proxy-pattern), not in
  the low-trust CLI.
- Clipboard integration for `get`: another plaintext egress to defend.
- Cryptographically signed audit log: out of scope for v1 (mode `0600` only).

## Supply-chain posture

`go.mod` pins `toolchain go1.26.4` for the patched stdlib (closes 11 reachable CVEs in
`crypto/tls`, `crypto/x509`, `net`, `net/textproto`, `net/url`, `os`). `golang.org/x/crypto` is pinned at
`v0.52.0`. Two residual vulns in transitive `dvsekhvalnov/jose2go` (via `99designs/keyring`)
are confirmed not reachable from opq by `govulncheck`; they wait on the upstream PR rather
than a local vendor-and-patch. Re-run `mise run vulncheck` after any dependency bump.
