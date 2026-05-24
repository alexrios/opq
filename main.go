package main

import (
	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"
)

type CLI struct {
	Set    SetCmd    `cmd:"" help:"Store a secret. Reads value from stdin (or TTY prompt if interactive). The value never appears in argv."`
	Get    GetCmd    `cmd:"" help:"Print a secret to stdout. Refuses to run unless stdout is a TTY (blocks AI piping)."`
	List   ListCmd   `cmd:"" help:"List secret names. Never prints values."`
	Delete DeleteCmd `cmd:"" help:"Delete a secret."`
	Exec   ExecCmd   `cmd:"" help:"Run a command with secrets injected as environment variables."`
	Audit  AuditCmd  `cmd:"" help:"Show recent audit-log entries."`
	MCP    MCPCmd    `cmd:"mcp" help:"Run as a Model Context Protocol server over stdio."`
}

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	cli := CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("opq"),
		kong.Description("opaque — AI-safe secrets gatekeeper. Stores secrets in your OS keyring and lets programs use them without ever exposing plaintext to the caller."),
		kong.UsageOnError(),
	)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
