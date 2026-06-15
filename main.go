package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"
)

// version is the binary version. It is overridable at link time via
// `-ldflags "-X main.version=..."` (set by the mise build/install tasks). When
// left empty, resolveVersion falls back to the module version Go records for
// `go install module@tag`, then to "dev" for a bare source build.
var version string

type CLI struct {
	Version kong.VersionFlag `help:"Print the opq version and exit."`
	Set     SetCmd           `cmd:"" help:"Store a secret. Reads value from stdin (or TTY prompt if interactive). The value never appears in argv."`
	Get     GetCmd           `cmd:"" help:"Print a secret to stdout. Refuses to run unless stdout is a TTY (blocks AI piping)."`
	List    ListCmd          `cmd:"" help:"List secret names and their TTL/revocation status. Never prints values."`
	Delete  DeleteCmd        `cmd:"" help:"Delete a secret (and any TTL/revocation record)."`
	Revoke  RevokeCmd        `cmd:"" help:"Revoke a secret: wipe its value now and leave a revoked tombstone."`
	Prune   PruneCmd         `cmd:"" help:"Delete all expired secrets (use --dry-run to preview)."`
	Exec    ExecCmd          `cmd:"" help:"Run a command with secrets injected as environment variables."`
	Audit   AuditCmd         `cmd:"" help:"Show recent audit-log entries."`
	MCP     MCPCmd           `cmd:"mcp" help:"Run as a Model Context Protocol server over stdio."`
}

func main() {
	// Indirect through run() so that os.Exit fires AFTER all defers, most
	// importantly memguard.Purge, which zeroes any locked pages still alive.
	// Calling os.Exit directly anywhere deeper would skip those defers and
	// leave secret pages reclaimed-but-not-zeroed.
	os.Exit(run())
}

func run() int {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	cli := CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("opq"),
		kong.Description("opq: AI-safe secrets gatekeeper. Stores secrets in your OS keyring and lets programs use them without ever exposing plaintext to the caller."),
		kong.UsageOnError(),
		kong.Vars{"version": resolveVersion()},
	)
	err := ctx.Run()
	if err == nil {
		return 0
	}
	// Child-process exit codes are wrapped in *exitCodeError so we can
	// unwind through Run()'s defers before exiting; propagate the code
	// here without printing (the child already wrote its own output).
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	fmt.Fprintln(os.Stderr, "opq:", err)
	return 1
}

// resolveVersion reports the binary version, preferring the link-time value,
// then the module version Go embeds for `go install module@tag`, then "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}
