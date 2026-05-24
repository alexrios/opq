package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type ExecCmd struct {
	Env      []string `name:"env" short:"e" help:"Inject a secret as an environment variable for the child. Format: VAR=secret_name. Repeatable."`
	NoRedact bool     `name:"no-redact" help:"DISABLE output redaction. Subprocess stdout/stderr passes through unchanged. Logged loudly to the audit log."`
	Command  []string `arg:"" passthrough:"" help:"Command and arguments to run. Use -- to separate from opq flags."`
}

func (c *ExecCmd) Run() error {
	// kong's passthrough captures "--" literally as the first positional;
	// strip it so users can write the conventional `opq exec ... -- cmd`.
	if len(c.Command) > 0 && c.Command[0] == "--" {
		c.Command = c.Command[1:]
	}
	if len(c.Command) == 0 {
		return errors.New("missing command to run; example: opq exec --env OPENAI_API_KEY=openai_api_key -- curl ...")
	}

	envMappings, err := parseEnvMappings(c.Env)
	if err != nil {
		return err
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	// Resolve all secrets up front so we fail before spawning anything.
	type resolved struct {
		envName string
		buf     *Buffer
	}
	resolvedSecrets := make([]resolved, 0, len(envMappings))
	cleanup := func() {
		for _, r := range resolvedSecrets {
			r.buf.Destroy()
		}
	}
	defer cleanup()

	for _, m := range envMappings {
		buf, err := backend.Get(ctx, m.secretName)
		if err != nil {
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: m.secretName, Caller: callerTag(), Message: err.Error()})
			return fmt.Errorf("resolve %s: %w", m.secretName, err)
		}
		resolvedSecrets = append(resolvedSecrets, resolved{envName: m.envName, buf: buf})
		_ = AppendAudit(AuditEvent{Action: ActionExecInject, SecretName: m.secretName, Caller: callerTag()})
	}

	if c.NoRedact {
		_ = AppendAudit(AuditEvent{Action: ActionRedactionDisabled, Caller: callerTag(), Message: strings.Join(c.Command, " ")})
	}

	// Build child env: copy parent, drop our internal vars, append secrets.
	childEnv := filterParentEnv(os.Environ())
	for _, r := range resolvedSecrets {
		// We must construct one string per env var. The Go runtime copies
		// these into the exec's argv-equivalent. Keep the lifetime short:
		// build, hand to exec.Cmd, then wipe our local copies.
		childEnv = append(childEnv, r.envName+"="+string(r.buf.Bytes()))
	}

	cmd := exec.CommandContext(ctx, c.Command[0], c.Command[1:]...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin

	var stdoutW, stderrW = os.Stdout, os.Stderr
	var stdoutRW, stderrRW *RedactingWriter
	if !c.NoRedact {
		named := make([]NamedSecret, 0, len(resolvedSecrets))
		for _, r := range resolvedSecrets {
			named = append(named, NamedSecret{Name: r.envName, Value: r.buf.Bytes()})
		}
		stdoutRW = NewRedactingWriter(os.Stdout, named)
		stderrRW = NewRedactingWriter(os.Stderr, named)
		cmd.Stdout = stdoutRW
		cmd.Stderr = stderrRW
		// Destroy after subprocess exits — done below.
		defer stdoutRW.Destroy()
		defer stderrRW.Destroy()
		_ = stdoutW // suppress unused if branch differs
		_ = stderrW
	} else {
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW
	}

	// Forward signals to the child so users can ^C cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start child: %w", err)
	}
	// childEnv contains strings holding the secret values. Go strings are
	// immutable, so we cannot wipe them in place — they persist on the heap
	// until GC reclaims them. The mlocked source lives in resolvedSecrets
	// and is Destroyed via defer above; the leak window is the time between
	// exec.Start (which copies env into the child) and GC of childEnv.

	go func() {
		sig := <-sigCh
		_ = cmd.Process.Signal(sig)
	}()

	waitErr := cmd.Wait()
	if !c.NoRedact {
		_ = stdoutRW.Flush()
		_ = stderrRW.Flush()
	}

	if waitErr != nil {
		// Propagate the child's exit code.
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		return waitErr
	}
	return nil
}

type envMapping struct {
	envName    string
	secretName string
}

func parseEnvMappings(specs []string) ([]envMapping, error) {
	out := make([]envMapping, 0, len(specs))
	seen := map[string]bool{}
	for _, s := range specs {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq == len(s)-1 {
			return nil, fmt.Errorf("invalid --env %q (expected VAR=secret_name)", s)
		}
		envName, secretName := s[:eq], s[eq+1:]
		if !validEnvName(envName) {
			return nil, fmt.Errorf("invalid env var name %q", envName)
		}
		if seen[envName] {
			return nil, fmt.Errorf("env var %q specified twice", envName)
		}
		seen[envName] = true
		out = append(out, envMapping{envName: envName, secretName: secretName})
	}
	return out, nil
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// filterParentEnv drops internal OPQ_* vars from the inherited env so
// they cannot leak into the subprocess.
func filterParentEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "OPQ_") {
			continue
		}
		out = append(out, e)
	}
	return out
}
