package main

import "strings"

// Variables on this list change how the dynamic linker, libc, or common
// interpreters locate code, libraries, or config. Allowing an AI caller
// of run_with_secrets (or the operator via --env on the CLI) to set any
// of these to a secret value would amount to RCE — PATH hijacking,
// LD_PRELOAD library injection, BASH_ENV startup-file sourcing, etc.
//
// Scope: this deny-list applies only to *injected* env vars (the --env
// flag on `opq exec` and the Env map on the MCP run_with_secrets tool).
// It deliberately does NOT touch the parent environment of opq itself,
// which is the operator's own shell and out of opaque's threat model
// (see filterParentEnv in cmd_exec.go for the parent-env policy).
var blockedEnv = map[string]bool{
	"PATH":              true,
	"IFS":               true,
	"HOME":              true,
	"SHELL":             true,
	"TERM":              true,
	"TMPDIR":            true,
	"TZ":                true,
	"BASH_ENV":          true,
	"ENV":               true,
	"PROMPT_COMMAND":    true,
	"PYTHONPATH":        true,
	"PYTHONSTARTUP":     true,
	"NODE_OPTIONS":      true,
	"NODE_PATH":         true,
	"PERL5LIB":          true,
	"PERL5OPT":          true,
	"PERLLIB":           true,
	"RUBYOPT":           true,
	"RUBYLIB":           true,
	"GEM_HOME":          true,
	"GEM_PATH":          true,
	"BUNDLE_GEMFILE":    true,
	"JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS":     true,
	"JDK_JAVA_OPTIONS":  true,
	"JAVA_HOME":         true,
	"CLASSPATH":         true,
	"PYTHONHOME":        true,
	"GIT_SSH":           true,
	"GIT_SSH_COMMAND":   true,
	// CVE-2023-4911 ("Looney Tunables"): glibc reads this tunable env
	// var early in ld.so before applying privilege drops. Not LD_-prefixed.
	"GLIBC_TUNABLES": true,
	// glibc resolver lookup files & options. Crafted values redirect
	// DNS/hostname resolution to attacker-controlled paths.
	"LOCALDOMAIN": true,
	"HOSTALIASES": true,
	"RES_OPTIONS": true,
	// glibc malloc tracing — points to a file the libc will write to.
	"MALLOC_TRACE": true,
	// glibc/gettext locale path — file inclusion.
	"NLSPATH": true,
}

// Prefix bans for the dynamic-linker family and well-known GLib / NSS
// escape hatches. Match is case-sensitive (env names are case-sensitive
// on POSIX); cf. validEnvName.
var blockedPrefixes = []string{"LD_", "DYLD_", "NSS_", "GIO_", "GCONV_"}

// isBlockedEnvName reports whether an env var name is on the
// injected-env deny-list. Returns true for any name in blockedEnv or
// starting with any prefix in blockedPrefixes.
func isBlockedEnvName(s string) bool {
	if blockedEnv[s] {
		return true
	}
	for _, p := range blockedPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
