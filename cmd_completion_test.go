package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestCompletion_AllShellsContainCommandsFlagsAndSafeDynamicLookup(t *testing.T) {
	subcommands := []string{
		"set", "get", "list", "info", "delete", "revoke",
		"prune", "exec", "audit", "doctor", "migrate", "completion", "mcp",
	}
	flags := []string{
		"help", "version",
		"ttl", "keep-ttl", "no-clobber", "trim",
		"plaintext",
		"long", "json", "status",
		"dry-run", "include-revoked",
		"overwrite", "delete-legacy",
		"env", "sandbox", "no-redact",
		"tail", "all", "caller", "action", "secret",
	}
	enumTokens := []string{
		"none net full",
		"cli mcp",
		"bash zsh fish",
	}

	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var buf bytes.Buffer
			if err := runCompletion(shell, &buf); err != nil {
				t.Fatalf("runCompletion(%q) failed: %v", shell, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("empty completion script for %s", shell)
			}

			for _, sub := range subcommands {
				if !strings.Contains(out, sub) {
					t.Errorf("%s completion missing subcommand %q", shell, sub)
				}
			}
			for _, fl := range flags {
				needle := "--" + fl
				if shell == "fish" {
					needle = "-l " + fl
				}
				if !strings.Contains(out, needle) {
					t.Errorf("%s completion missing flag %q", shell, needle)
				}
			}
			for _, tok := range enumTokens {
				if !strings.Contains(out, tok) {
					t.Errorf("%s completion missing enum values %q", shell, tok)
				}
			}
			if !strings.Contains(out, "opq list 2>/dev/null | cut -f1") {
				t.Errorf("%s completion missing safe dynamic secret-name helper 'opq list 2>/dev/null | cut -f1'", shell)
			}
			// Security check: completion scripts must never invoke `opq get`.
			if strings.Contains(out, "opq get") {
				t.Errorf("SECURITY VIOLATION: %s completion must never invoke 'opq get'", shell)
			}
		})
	}
}

func TestCompletion_UnsupportedShell(t *testing.T) {
	for _, bad := range []string{"", "powershell", "tcsh", "sh"} {
		var buf bytes.Buffer
		if err := runCompletion(bad, &buf); err == nil {
			t.Errorf("runCompletion(%q) succeeded, want error", bad)
		}
	}
}

func TestCompletion_ShellSyntaxValid(t *testing.T) {
	checks := []struct {
		shell string
		bin   string
		args  []string
	}{
		{shell: "bash", bin: "bash", args: []string{"-n"}},
		{shell: "zsh", bin: "zsh", args: []string{"-n"}},
		{shell: "fish", bin: "fish", args: []string{"-n"}},
	}

	for _, tc := range checks {
		t.Run(tc.shell, func(t *testing.T) {
			binPath, err := exec.LookPath(tc.bin)
			if err != nil {
				t.Skipf("%s not installed in PATH", tc.bin)
			}
			script, err := completionScript(tc.shell)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binPath, tc.args...)
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s %v failed on generated %s script: %v\n%s", tc.bin, tc.args, tc.shell, err, string(out))
			}
		})
	}
}
