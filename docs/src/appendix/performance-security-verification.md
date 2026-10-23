# Performance and Security Verification

Verified on 2026-10-23 using Go 1.26.10, macOS/arm64, Apple M4. Tests use synthetic
values and temporary files; no stored credentials were created, changed, or deleted.
The comparison baseline is commit `db0f6cf`.

## Measured performance

Both implementations were benchmarked with Go 1.26.10. Values below are medians of
three runs. These are isolated synthetic workloads, not end-to-end CLI latency claims.

| Workload | Baseline | Updated |
| --- | ---: | ---: |
| Ordinary output, one secret | 77.56 MB/s | 479.62 MB/s |
| Ordinary output, eight secrets | 10.05 MB/s | 324.43 MB/s |
| Ordinary output, 32 secrets | 2.54 MB/s | 171.37 MB/s |
| Redaction allocations per steady-state write | 81,920 B, 2 allocations | 0 B, 0 allocations |
| Last 20 records of a 10 MiB audit log | 8.456 ms | 0.412 ms |
| Allocations for that audit tail | 38,309,705 B | 19,984 B |

The updated 32-secret redactor also reached 98.8 MB/s with shared-prefix output,
and 89.86 MB/s with 31-byte split writes. Audit timings showed some concurrent-build
noise; allocation counts were stable. Audit writes still call `fsync`.

Re-run the committed benchmarks:

```sh
mise exec -- go test -run '^$' -bench 'Benchmark(RedactingWriter|AuditTail)' -benchmem -benchtime=300ms -count=3
```

## Regression evidence

| Property | Executable evidence |
| --- | --- |
| A writer follows another process's rotation | `TestAppendAudit_ReopensAfterOtherProcessRotation` |
| Backward tails preserve full-read semantics | `FuzzAuditTailMatchesFullRead`, boundary and rotation tests |
| A canceled audit wait releases an MCP execution slot | `TestRunWithSecretsDeadlineReleasesSlotWhileAuditLocked` |
| Readers cannot observe a replacement value before its TTL | `TestStoreSecret_ReaderCannotObserveValueBeforeTTL` |
| Interrupted writes block reads until explicit recovery | `TestStoreSecret_IncompleteUpdatesFailClosed` |
| Lock identity survives different HOME/XDG environments | `TestPolicyLock_IdentityIndependentOfEnvironment`, cross-process tests |
| Emergency revoke wipes a value despite unreadable policy | `TestRevokeSecret_UnreadableMetadataStillWipesValue` |
| Split encoded output remains redacted | `FuzzRedactEncodedChunkBoundaries` |
| Child deadlines and inherited pipes are bounded | `TestProcessDeadlineClosesDescendantPipes`, `TestSandboxMCP_DeadlineKillsDescendantsAndAudits` |
| Redirected stdin retains controlling-terminal access | `TestCLIProcessReadsControllingTTYWithRedirectedStdin` |
| INT/TERM/HUP run graceful cleanup and remove the child group | `TestCLIInterruptCleansPrivateChildGroup` |
| Server cancellation and abrupt client EOF stop active SDK handlers | `TestMCPLifetimeCancelsActiveSDKTool`, `TestMCPDisconnectCancelsActiveSDKTool` |
| Network, credential and state masks are enforced | Platform-specific `TestSandbox` integration tests |
| Network-enabled macOS runs cannot connect to protected Unix sockets or their aliases | `TestSandboxSeatbelt_NetworkAllowedBlocksProtectedUnixSockets`, `TestSandboxSeatbelt_NetworkAllowedBlocksSymlinkedDockerSocket` |
| Proxy calls are fixed, responses narrow, subprocesses reaped | In-memory and real-stdio tests in `examples/policy-proxy` |
| EOF or SIGTERM cancels an active proxy operation before upstream cleanup | `TestProxyStdioCancelsActiveOperationOnDisconnectAndSignal` |

Before the rotation fix, its new two-process regression failed. Before the CLI TTY fix,
the redirected-input PTY regression timed out; the foreground-compatible version passed. Removing the explicit server-lifetime
binding made both SDK cancellation/disconnect tests fail at their one-second deadline;
the bound version passed.
Proxy stdio tests also started a 60-second operation, then disconnected or sent
SIGTERM. Both paths canceled the operation and reaped the upstream process in
3–4 ms in repeated local runs.

The original subprocess pattern let an 80 ms deadline wait roughly 780 ms for a
descendant's pipes. New tests use a 10-second descendant and require bounded return.

Re-run functional verification:

```sh
mise run check
mise exec -- go test -race -count=1 -timeout=2m ./...
mise exec -- go test -race -tags=integration -run '^TestSandbox' -count=1 -timeout=2m ./...
mise exec -- go test -run '^$' -fuzz '^FuzzRedactEncodedChunkBoundaries$' -fuzztime=5s -parallel=2
mise exec -- go test -run '^$' -fuzz '^FuzzAuditTailMatchesFullRead$' -fuzztime=5s -parallel=2
mise run vulncheck
mise run docs
```

The previous Go 1.26.4 scan reported 11 reachable standard-library advisories. The
Go 1.26.10 scan reports zero reachable advisories; uncalled affected dependencies
are still reported separately. This is evidence about known advisories, not a proof
that the program contains no vulnerabilities.

## Boundaries

macOS runtime checks run locally. Linux tests cross-compile, and CI now runs Linux
and macOS race, sandbox and fuzz jobs. Linux runtime execution requires a working
bubblewrap host; a missing sandbox fails the selected integration suite. Remote CI
results must be checked separately.

Native keyring calls and filesystem syscalls cannot be canceled in flight. Process
groups provide cleanup, not containment of descendants that deliberately escape them.
Arbitrary commands still have output and permitted-network channels; padding is
removed because it cannot close those channels. The fixed-operation proxy returns
status only and requires operator-controlled programs, configuration and inputs.

## macOS Unix-socket connection regression

The new live-socket test failed before the fix for Docker, GPG, home SSH and
`SSH_AUTH_SOCK` endpoints: file-read restrictions did not stop `connect(2)`. Explicit
Unix-socket network-outbound denials now reject those connections, including canonical
paths, symlink aliases, and a Docker socket symlink pointing outside the home directory.
Positive controls verify that ordinary HTTP and custom unprotected Unix sockets remain
available. The system Docker socket also receives an explicit connection-denial rule.

```sh
mise exec -- go test -race -tags=integration -run '^TestSandboxSeatbelt_Network' -count=2 -timeout=45s .
```

All socket servers in these tests are synthetic. No real container daemon, SSH/GPG
agent, or stored credential is accessed.
