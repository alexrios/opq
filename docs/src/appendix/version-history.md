# Version & Hardening History

`opq`'s security posture was built incrementally, with several rounds of adversarial
review closing confirmed exploits. This appendix records that history so the reasoning
behind each control is preserved.

## v1.2.1 (current)

Release tooling and documentation. Releases are now cut by GoReleaser on tag push
(cross-platform builds, the GitHub release, and the Homebrew cask in
[`alexrios/homebrew-tap`](https://github.com/alexrios/homebrew-tap)), so
`brew install alexrios/tap/opq` tracks each release. Documentation adds the Homebrew
install path and a round of accuracy fixes from a content review.

## v1.2.0 (macOS support)

First release supported on macOS as well as Linux. Adds a native macOS Keychain secrets
backend and a `sandbox-exec` (Seatbelt) subprocess sandbox, and wires up `opq --version`.

- macOS Keychain backend. Secrets storage, previously Linux-only (Secret Service), now
  has a native macOS implementation (`backend_darwin.go`) using the login Keychain via
  `99designs/keyring`, with items namespaced under the `opq` service. `OpenDefaultBackend`
  is split per-OS (`backend_linux.go` / `backend_darwin.go` / `backend_other.go`), each
  restricted to a single allowed backend so opq never falls back to an unencrypted file
  store. `KeychainTrustApplication` lets the opq binary read back its own secrets without a
  per-call prompt; `KeychainSynchronizable` is off so secrets never reach iCloud. The
  Keychain backend requires a CGO-enabled build (it links the Security framework). With
  this and the macOS sandbox below, opq is now supported on macOS as well as Linux.
- macOS sandbox backend. The subprocess sandbox, previously Linux-only (`bwrap`), now
  has a native macOS implementation using `sandbox-exec` (Seatbelt / SBPL) in
  `sandbox_darwin.go`. It maps the same `SandboxNet` / `SandboxNetAllowed` /
  `SandboxFull` profiles via `(allow default)` + targeted denies, with two documented
  divergences: writes are denied wholesale under `SandboxNet` (Seatbelt cannot overlay
  an empty tmpfs, which is strictly stronger against the two-call exfil chain), and
  `SandboxFull` is allow-default-with-denies rather than deny-default.
  See [The Sandbox](../security/sandbox.md#macos-seatbelt).

## v1.1.6

Tooling and naming. The project was renamed from `opaque` to `opq` so that
`go install github.com/alexrios/opq@latest` produces the `opq` binary directly (Go names
the binary after the module path's last element, with no `-o` override). Adds universal
`mise` tasks and mise-based CI. The `OPQ_*` env prefix and `~/.local/state/opq/` audit
directory date from this rename.

## v1.1.4 (encoding, output-volume, credential-agent hardening)

- The redactor registers base64 (std/URL, padded/raw) and hex (lower/upper) forms of each
  secret, closing the "just base64 it" evasion (see [The Redactor](../security/redactor.md)).
- AI-visible stdout/stderr lengths are padded to fixed buckets (1/4/16/64/256 KiB),
  collapsing the length side channel from ~17 bits to ~2.3 bits per call.
- Container-runtime and system-D-Bus masks (P0-1, P1-2). `--ro-bind / /` left Docker,
  containerd, and similar sockets and `/run/dbus` `connect(2)`-reachable. An AI could spawn
  a privileged container (`-v /:/host`) or broadcast the secret as an Avahi mDNS TXT record.
  Closed by `appendRuntimeSocketMasks`.
- Home-directory credential-agent masks. `$HOME/.gnupg` and `$HOME/.docker/run/docker.sock`
  are masked, closing gpg-agent signing and rootless-Docker reach-out.

## v1.1.3 (read-only host root)

- `--ro-bind / /` replaced `--dev-bind / /`. The read-write root allowed a two-call exfil
  chain: write the secret to `/var/tmp` in one call, `cat` it back in a later empty-secret
  call where the redactor was a pass-through. Binding read-only kills the persistent write;
  within-call scratch moved to tmpfs masks (P0-1).
- The `exec --no-redact` re-entry gate. An AI calling
  `run_with_secrets({command:"opq", args:["exec","--no-redact",...]})` bypassed redaction;
  `--no-redact` is now gated like `get --plaintext`.
- The audit-log directory is masked under SandboxNet, so the AI cannot `cat` the operator's
  log from inside the sandbox.

## v1.1.2 (env deny-list, audit integrity, self-logging)

- The loader env deny-list. `LD_PRELOAD` / `PATH` / `BASH_ENV` and a broad family of
  loader-honored names are refused at both the CLI and MCP injection points (see
  [Environment Deny-List](../reference/env-deny-list.md)).
- Cross-process audit integrity via the `audit.lock` flock pattern.
- Audit-error sanitization and the AI-visible allowlist. Backend and exec errors map to a
  fixed taxonomy; the AI's `mcp_run` message view keeps only `timed_out`.
- `audit_tail` self-logging. Each MCP `audit_tail` call records its own entry, so scraping
  is visible.
- A functional sandbox startup probe. `opq mcp` runs a no-op `bwrap` namespace probe and
  stops if it fails.
- Hard input caps. Env-var names ≤ 256 bytes; secret names match `[A-Za-z0-9_.-]{1,128}`;
  `args` ≤ 256 entries.

## v1.1.1 (the D-Bus and keyring mask)

- `--tmpfs /run/user`. A confirmed exploit: an AI inside the network-blocked sandbox
  reached the session D-Bus socket at `/run/user/$UID/bus` and recovered keyring secrets
  directly. `--unshare-net` does not help, because AF_UNIX sockets are
  filesystem-namespaced. Masking `/run/user` and `/tmp` closed it.

## v1.0 (the baseline)

- Secret Service (libsecret) backend on Linux via `99designs/keyring`.
- `memguard` mlocked buffers for all secret bytes.
- TTY-gated `get`, argv-free `set`, default output redaction.
- MCP server with `list_secrets` / `run_with_secrets` / `audit_tail` and no
  `get_secret_value`.
- Network-blocked, PID-isolated bubblewrap sandbox for MCP subprocesses.

## Re-verifying

After any dependency bump:

```sh
mise run vulncheck     # govulncheck ./...
mise run check         # vet + test + build
```

The security invariants are locked by unit tests named after the exploit they close (for
example `TestSandboxNet_DockerSocketUnreachable`, `TestExecCmdRun_GateInvokedBeforeKeyring`,
`TestRedact_EncodingBypass_Base64Std`). A failing test of this kind means a control
regressed.
