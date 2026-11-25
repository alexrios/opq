package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
)

func TestResolveVersion_PrefersLinkTimeValue(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Fatalf("resolveVersion() = %q, want the link-time value v9.9.9", got)
	}
}

func TestResolveVersion_FallsBackWhenUnset(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	// With no link-time value and no module version under `go test`, the
	// resolver must still return a non-empty marker rather than "".
	version = ""
	if got := resolveVersion(); got == "" {
		t.Fatal("resolveVersion() returned empty string; want a fallback marker")
	}
}

func TestCLI_NewCommandsRegisteredInKong(t *testing.T) {
	cases := []struct {
		args        []string
		wantCommand string
		check       func(t *testing.T, cli *CLI)
	}{
		{
			args:        []string{"doctor"},
			wantCommand: "doctor",
			check: func(t *testing.T, cli *CLI) {
				if cli.Doctor.JSON {
					t.Error("Doctor.JSON = true, want false")
				}
			},
		},
		{
			args:        []string{"doctor", "--json"},
			wantCommand: "doctor",
			check: func(t *testing.T, cli *CLI) {
				if !cli.Doctor.JSON {
					t.Error("Doctor.JSON = false, want true")
				}
			},
		},
		{
			args:        []string{"info", "openai_api_key"},
			wantCommand: "info <name>",
			check: func(t *testing.T, cli *CLI) {
				if cli.Info.Name != "openai_api_key" || cli.Info.JSON {
					t.Errorf("unexpected Info fields: %+v", cli.Info)
				}
			},
		},
		{
			args:        []string{"info", "openai_api_key", "--json"},
			wantCommand: "info <name>",
			check: func(t *testing.T, cli *CLI) {
				if cli.Info.Name != "openai_api_key" || !cli.Info.JSON {
					t.Errorf("unexpected Info fields: %+v", cli.Info)
				}
			},
		},
		{
			args:        []string{"completion", "bash"},
			wantCommand: "completion <shell>",
			check: func(t *testing.T, cli *CLI) {
				if cli.Completion.Shell != "bash" {
					t.Errorf("Completion.Shell = %q, want bash", cli.Completion.Shell)
				}
			},
		},
		{
			args:        []string{"completion", "zsh"},
			wantCommand: "completion <shell>",
			check: func(t *testing.T, cli *CLI) {
				if cli.Completion.Shell != "zsh" {
					t.Errorf("Completion.Shell = %q, want zsh", cli.Completion.Shell)
				}
			},
		},
		{
			args:        []string{"completion", "fish"},
			wantCommand: "completion <shell>",
			check: func(t *testing.T, cli *CLI) {
				if cli.Completion.Shell != "fish" {
					t.Errorf("Completion.Shell = %q, want fish", cli.Completion.Shell)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var cli CLI
			parser, err := kong.New(&cli,
				kong.Name("opq"),
				kong.Writers(&bytes.Buffer{}, &bytes.Buffer{}),
				kong.Exit(func(int) {}),
				kong.Vars{"version": "test"},
			)
			if err != nil {
				t.Fatalf("kong.New failed: %v", err)
			}
			kctx, err := parser.Parse(tc.args)
			if err != nil {
				t.Fatalf("Parse(%v) failed: %v", tc.args, err)
			}
			if kctx.Command() != tc.wantCommand {
				t.Errorf("Command() = %q, want %q", kctx.Command(), tc.wantCommand)
			}
			tc.check(t, &cli)
		})
	}
}

func TestCLI_CompletionRejectsInvalidShell(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli,
		kong.Name("opq"),
		kong.Writers(&bytes.Buffer{}, &bytes.Buffer{}),
		kong.Exit(func(int) {}),
		kong.Vars{"version": "test"},
	)
	if err != nil {
		t.Fatalf("kong.New failed: %v", err)
	}
	if _, err := parser.Parse([]string{"completion", "tcsh"}); err == nil {
		t.Fatal("expected parse error for unsupported shell 'tcsh'")
	}
}

func TestCLI_GetHelpMentionsPlaintextAndHumanGate(t *testing.T) {
	var cli CLI
	var out bytes.Buffer
	parser, err := kong.New(&cli,
		kong.Name("opq"),
		kong.Writers(&out, &out),
		kong.Exit(func(int) {}),
		kong.Vars{"version": "test"},
	)
	if err != nil {
		t.Fatalf("kong.New failed: %v", err)
	}

	var getHelp string
	for _, child := range parser.Model.Children {
		if child.Name == "get" {
			getHelp = child.Help
			break
		}
	}
	if getHelp == "" {
		t.Fatal("get subcommand not found in Kong CLI model")
	}
	for _, want := range []string{"--plaintext", "OPQ_I_AM_HUMAN=1", "TTY"} {
		if !strings.Contains(getHelp, want) {
			t.Errorf("top-level get help %q missing %q", getHelp, want)
		}
	}
}
