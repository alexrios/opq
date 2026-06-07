// Package main — input-name validation shared across the CLI and MCP surfaces.
//
// Both checks bound caller-controlled bytes (secret names, env-var names) before
// they reach the keyring, a subprocess env table, or the operator audit log.
// They are name-shape guards only — the env-NAME *deny-list* (PATH, LD_*, ...)
// lives in env_policy.go.
package main

import "regexp"

// secretNameRe constrains a secret name (CLI --env VAR=name or the MCP Env map)
// to [A-Za-z0-9_.-]{1,128}. Tighter than the keyring allows, to keep
// caller-controlled bytes out of the operator-visible audit log and bound line
// size.
var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// validSecretName reports whether name has the accepted shape (false if empty).
func validSecretName(name string) bool {
	return secretNameRe.MatchString(name)
}

// maxEnvNameBytes caps the length of an injected env-var name. Real POSIX
// names are short (PATH, HOME, OPENAI_API_KEY, ...); the cap exists to bound
// the env-table size a single --env / Env-map entry can produce, not to
// enforce a strict POSIX rule.
const maxEnvNameBytes = 256

// validEnvName reports whether s is an acceptable injected env-var name:
// non-empty, within maxEnvNameBytes, and matching [A-Za-z_][A-Za-z0-9_]*.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > maxEnvNameBytes {
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
