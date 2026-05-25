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
			name: "secret name containing equals is kept whole",
			// IndexByte returns the FIRST '='; everything after it is the
			// secret name. This lets secret names contain '=' safely.
			in: []string{"X=foo=bar=baz"},
			want: want{mappings: []envMapping{
				{envName: "X", secretName: "foo=bar=baz"},
			}},
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
