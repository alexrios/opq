package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvMappings(t *testing.T) {
	type want struct {
		mappings []envMapping
		errSub   string // substring of expected error message; empty = no error
	}
	cases := []struct {
		name string
		in   []string
		want want
	}{
		{
			name: "empty input returns empty slice",
			in:   nil,
			want: want{mappings: []envMapping{}},
		},
		{
			name: "single valid mapping",
			in:   []string{"API_KEY=openai_api_key"},
			want: want{mappings: []envMapping{{envName: "API_KEY", secretName: "openai_api_key"}}},
		},
		{
			name: "multiple valid mappings preserve order",
			in:   []string{"A=one", "B=two", "C=three"},
			want: want{mappings: []envMapping{
				{envName: "A", secretName: "one"},
				{envName: "B", secretName: "two"},
				{envName: "C", secretName: "three"},
			}},
		},
		{
			name: "secret name containing equals is rejected by shape validator",
			// IndexByte returns the FIRST '='; everything after it would be
			// the secret name. J-14 rejects names outside [A-Za-z0-9_.-]{1,128}.
			in:   []string{"X=foo=bar=baz"},
			want: want{errSub: "invalid secret name"},
		},
		{
			name:   "missing equals is rejected",
			in:     []string{"API_KEY"},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "leading equals is rejected (empty env name)",
			in:     []string{"=openai_api_key"},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "trailing equals is rejected (empty secret name)",
			in:     []string{"API_KEY="},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "env name starting with digit is rejected",
			in:     []string{"1FOO=bar"},
			want:   want{errSub: "invalid env var name"},
		},
		{
			name:   "env name with dash is rejected",
			in:     []string{"FOO-BAR=baz"},
			want:   want{errSub: "invalid env var name"},
		},
		{
			name:   "duplicate env name is rejected",
			in:     []string{"API=one", "API=two"},
			want:   want{errSub: `env var "API" specified twice`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEnvMappings(tc.in)
			if tc.want.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (result=%v)", tc.want.errSub, got)
				}
				if !strings.Contains(err.Error(), tc.want.errSub) {
					t.Fatalf("expected error containing %q, got %q", tc.want.errSub, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// reflect.DeepEqual treats nil slice and empty slice as different;
			// normalize to empty slice for comparison.
			if got == nil {
				got = []envMapping{}
			}
			if !reflect.DeepEqual(got, tc.want.mappings) {
				t.Fatalf("mappings mismatch:\n  got:  %#v\n  want: %#v", got, tc.want.mappings)
			}
		})
	}
}

func TestValidEnvName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"A", true},
		{"a", true},
		{"_", true},
		{"_FOO", true},
		{"FOO_BAR", true},
		{"foo123", true},
		{"FOO_BAR_BAZ_123", true},
		{"1FOO", false},     // leading digit
		{"9", false},        // single digit
		{"FOO-BAR", false},  // dash
		{"FOO.BAR", false},  // dot
		{"FOO BAR", false},  // space
		{"FOO=BAR", false},  // equals
		{"FOO/BAR", false},  // slash
		{"FOO\nBAR", false}, // newline
		{"FOO\x00", false},  // NUL
		{"é", false},        // non-ASCII letter
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := validEnvName(tc.in); got != tc.want {
				t.Fatalf("validEnvName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidEnvName_RejectsTooLong locks J-13: env-var names longer than
// maxEnvNameBytes (256) are rejected. The cap exists to bound the
// child-env table size a single --env / Env-map entry can produce.
func TestValidEnvName_RejectsTooLong(t *testing.T) {
	// 256 chars (boundary, accepted): "A_" + 254 'A's = 256.
	at256 := "A_" + strings.Repeat("A", 254)
	if len(at256) != 256 {
		t.Fatalf("at256 length = %d, want 256", len(at256))
	}
	if !validEnvName(at256) {
		t.Errorf("validEnvName(len=256) = false, want true")
	}
	// 257 chars (over the cap, rejected).
	at257 := "A_" + strings.Repeat("A", 255)
	if len(at257) != 257 {
		t.Fatalf("at257 length = %d, want 257", len(at257))
	}
	if validEnvName(at257) {
		t.Errorf("validEnvName(len=257) = true, want false")
	}
	// 255 chars (well under the cap, accepted).
	at255 := "A_" + strings.Repeat("A", 253)
	if len(at255) != 255 {
		t.Fatalf("at255 length = %d, want 255", len(at255))
	}
	if !validEnvName(at255) {
		t.Errorf("validEnvName(len=255) = false, want true")
	}
}

func TestFilterParentEnv(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "drops all OPQ_ vars",
			in:   []string{"OPQ_DEBUG=1", "OPQ_FOO=bar"},
			want: []string{},
		},
		{
			name: "keeps non-OPQ vars",
			in:   []string{"PATH=/usr/bin", "HOME=/home/x"},
			want: []string{"PATH=/usr/bin", "HOME=/home/x"},
		},
		{
			name: "mixed input keeps order of survivors",
			in:   []string{"PATH=/usr/bin", "OPQ_DEBUG=1", "HOME=/home/x", "OPQ_AUDIT_PATH=/tmp/a"},
			want: []string{"PATH=/usr/bin", "HOME=/home/x"},
		},
		{
			name: "OPQ_ prefix is case-sensitive (opq_ lowercase is kept)",
			// HasPrefix is case-sensitive; only the all-uppercase internal
			// prefix is filtered. This is intentional — user code may have
			// its own opq_-named vars.
			in:   []string{"opq_user_thing=1", "OPQ_REAL=2"},
			want: []string{"opq_user_thing=1"},
		},
		{
			name: "prefix-only match is dropped, substring match is kept",
			in:   []string{"OPQ_=empty", "MY_OPQ_VAR=fine"},
			want: []string{"MY_OPQ_VAR=fine"},
		},
		{
			name: "empty input returns empty slice",
			in:   []string{},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterParentEnv(tc.in)
			if got == nil {
				got = []string{}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("filterParentEnv mismatch:\n  got:  %#v\n  want: %#v", got, tc.want)
			}
		})
	}
}

func TestParseEnvMappings_RejectsBlockedNames(t *testing.T) {
	cases := []string{
		// exact-map entries
		"PATH=some_secret",
		"BASH_ENV=some_secret",
		"GLIBC_TUNABLES=some_secret",
		// LD_ prefix
		"LD_PRELOAD=some_secret",
		// NSS_ / GIO_ prefixes
		"NSS_HOSTS=some_secret",
		"GIO_USE_VFS=some_secret",
		// ERL_ prefix (newly added)
		"ERL_FLAGS=some_secret",
		"ERL_NEW_FUTURE_VAR=some_secret",
		// BASH_FUNC_ prefix (newly added); use a name valid per validEnvName
		// (no %%) since validEnvName runs before isBlockedEnvName.
		"BASH_FUNC_ls=some_secret",
		// GIT_CONFIG_ prefix (newly added)
		"GIT_CONFIG_KEY_0=some_secret",
		"GIT_CONFIG_VALUE_0=some_secret",
	}
	for _, spec := range cases {
		t.Run(spec, func(t *testing.T) {
			_, err := parseEnvMappings([]string{spec})
			if err == nil {
				t.Fatalf("expected error for blocked spec %q, got nil", spec)
			}
			if !strings.Contains(err.Error(), "deny-list") {
				t.Fatalf("expected deny-list in error, got %q", err.Error())
			}
		})
	}
}

// TestParseEnvMappings_RejectsBadSecretName locks J-14 on the CLI surface:
// a secret name outside [A-Za-z0-9_.-]{1,128} is rejected with the
// verbose CLI-style message ("invalid secret name") before any backend
// touch.
func TestParseEnvMappings_RejectsBadSecretName(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		// '=' is consumed by IndexByte as the separator, so the trailing
		// "bar=baz" becomes the secret name and fails the shape gate.
		{"secret_with_embedded_equals", "API=foo=bar=baz"},
		{"secret_with_space", "API=bad name"},
		{"secret_with_slash", "API=bad/path"},
		{"secret_with_dollar", "API=bad$value"},
		{"secret_too_long", "API=" + strings.Repeat("a", 129)},
		{"secret_with_newline", "API=bad\nname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnvMappings([]string{tc.spec})
			if err == nil {
				t.Fatalf("expected error for spec %q, got nil", tc.spec)
			}
			if !strings.Contains(err.Error(), "invalid secret name") {
				t.Fatalf("expected 'invalid secret name' in error, got %q", err.Error())
			}
		})
	}
}

func TestParseEnvMappings_LegitimateNameStillParses(t *testing.T) {
	got, err := parseEnvMappings([]string{"OPENAI_API_KEY=openai_api_key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []envMapping{{envName: "OPENAI_API_KEY", secretName: "openai_api_key"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mismatch:\n  got:  %#v\n  want: %#v", got, want)
	}
}

func TestExitCodeError(t *testing.T) {
	// Sanity check that the typed error reports the expected code and
	// carries a non-empty message (kong.FatalIfErrorf would otherwise
	// print an empty string if we ever fell back to it).
	e := &exitCodeError{code: 42}
	if e.ExitCode() != 42 {
		t.Fatalf("ExitCode = %d, want 42", e.ExitCode())
	}
	if e.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
}
