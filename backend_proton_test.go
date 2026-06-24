package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type fakeResp struct {
	out []byte
	err error
}

// fakeProton drives protonBackend without pass-cli: it matches on the joined
// argv and returns canned output, recording each call so tests can assert how
// many pass-cli invocations a Get made.
type fakeProton struct {
	t         *testing.T
	responses map[string]fakeResp
	calls     []string
}

func (f *fakeProton) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	r, ok := f.responses[key]
	if !ok {
		f.t.Fatalf("unexpected pass-cli call: %q", key)
		return nil, nil
	}
	// Return a fresh copy each call, mirroring a real subprocess: the backend
	// wipes returned buffers (memguard.WipeBytes), which must not corrupt the
	// shared fixture.
	return append([]byte(nil), r.out...), r.err
}

func newFakeProton(t *testing.T, responses map[string]fakeResp) *protonBackend {
	f := &fakeProton{t: t, responses: responses}
	return &protonBackend{bin: "pass-cli", vault: "v", field: "password", run: f.run}
}

const listCall = "item list v --output json"

func TestProtonBackend_List(t *testing.T) {
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[
			{"id":"i1","share_id":"s1","title":"github_token"},
			{"id":"i2","share_id":"s1","title":"aws_key"}
		]}`)},
	})
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if strings.Join(keys, ",") != "aws_key,github_token" {
		t.Fatalf("List: got %v", keys)
	}
}

func TestProtonBackend_Get(t *testing.T) {
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[{"id":"i1","share_id":"s1","title":"github_token"}]}`)},
		"item view --share-id s1 --item-id i1 --field password": {out: []byte("ghp_secret\n")},
	})
	buf, err := b.Get(context.Background(), "github_token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "ghp_secret" {
		t.Fatalf("Get: got %q", string(buf.Bytes()))
	}
}

func TestProtonBackend_GetCustomField(t *testing.T) {
	f := &fakeProton{t: t, responses: map[string]fakeResp{
		listCall: {out: []byte(`{"items":[{"id":"i1","share_id":"s1","title":"db"}]}`)},
		"item view --share-id s1 --item-id i1 --field api_key": {out: []byte("sk-xyz\n")},
	}}
	b := &protonBackend{bin: "pass-cli", vault: "v", field: "api_key", run: f.run}
	buf, err := b.Get(context.Background(), "db")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "sk-xyz" {
		t.Fatalf("Get custom field: got %q", string(buf.Bytes()))
	}
}

func TestProtonBackend_GetMissingTitle(t *testing.T) {
	f := &fakeProton{t: t, responses: map[string]fakeResp{
		listCall: {out: []byte(`{"items":[{"id":"i1","share_id":"s1","title":"other"}]}`)},
	}}
	b := &protonBackend{bin: "pass-cli", vault: "v", field: "password", run: f.run}
	if _, err := b.Get(context.Background(), "github_token"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(missing): want ErrSecretNotFound, got %v", err)
	}
	// A missing title must be decided from the list alone: no view call.
	if len(f.calls) != 1 {
		t.Fatalf("expected exactly 1 pass-cli call (list), got %d: %v", len(f.calls), f.calls)
	}
}

func TestProtonBackend_GetMetaKeyFastPath(t *testing.T) {
	f := &fakeProton{t: t, responses: map[string]fakeResp{}}
	b := &protonBackend{bin: "pass-cli", vault: "v", field: "password", run: f.run}
	if _, err := b.Get(context.Background(), metaKey("github_token")); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(meta/...): want ErrSecretNotFound, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("meta/ key must not spawn pass-cli, got calls: %v", f.calls)
	}
}

func TestProtonBackend_GetEmptyField(t *testing.T) {
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[{"id":"i1","share_id":"s1","title":"github_token"}]}`)},
		"item view --share-id s1 --item-id i1 --field password": {out: []byte("\n")},
	})
	if _, err := b.Get(context.Background(), "github_token"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(empty field): want ErrSecretNotFound, got %v", err)
	}
}

func TestProtonBackend_List1xContentTitle(t *testing.T) {
	// pass-cli 1.x embeds full item content in the listing: the title is at
	// content.title and the listing also carries the value, which List ignores.
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[
			{"id":"i1","share_id":"s1","content":{"title":"github_token","content":{"Login":{"password":"ghp_secret"}}}}
		]}`)},
		"item view --share-id s1 --item-id i1 --field password": {out: []byte("ghp_secret\n")},
	})
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "github_token" {
		t.Fatalf("List (1.x content.title): got %v", keys)
	}
	buf, err := b.Get(context.Background(), "github_token")
	if err != nil {
		t.Fatalf("Get (1.x content.title): %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "ghp_secret" {
		t.Fatalf("Get (1.x): got %q", string(buf.Bytes()))
	}
}

func TestProtonBackend_ListSkipsInvalidTitles(t *testing.T) {
	// Titles that aren't valid opq secret names (spaces, a meta/ prefix, a
	// newline) must not enter the AI-visible listing.
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[
			{"id":"i1","share_id":"s1","title":"good_name"},
			{"id":"i2","share_id":"s1","title":"has space"},
			{"id":"i3","share_id":"s1","title":"meta/sneaky"},
			{"id":"i4","share_id":"s1","title":"bad\nnewline"}
		]}`)},
	})
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "good_name" {
		t.Fatalf("List should surface only valid secret names, got %v", keys)
	}
}

func TestExecProtonRunner_CapsOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs head and /dev/zero")
	}
	// Emit more than maxProtonOutput; the runner must fail closed.
	n := maxProtonOutput + 1024
	_, err := execProtonRunner(context.Background(), "sh", "-c", "head -c "+strconv.Itoa(n)+" /dev/zero")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized pass-cli output should fail closed, got %v", err)
	}
}

func TestProtonBackend_DuplicateTitle(t *testing.T) {
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[
			{"id":"i1","share_id":"s1","title":"dup"},
			{"id":"i2","share_id":"s1","title":"dup"}
		]}`)},
	})
	// List dedups colliding titles to a single entry.
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "dup" {
		t.Fatalf("List with duplicate titles: want [dup], got %v", keys)
	}
	// Get fails closed on the ambiguous title rather than inject an arbitrary
	// item's value; the error is distinct from not-found.
	_, err = b.Get(context.Background(), "dup")
	if err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(ambiguous): want a distinct ambiguity error, got %v", err)
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("Get(ambiguous): error should say ambiguous, got %v", err)
	}
}

func TestProtonBackend_SetDeleteReadOnly(t *testing.T) {
	b := newFakeProton(t, map[string]fakeResp{})
	buf, _ := NewBufferFromBytes([]byte("x"))
	defer buf.Destroy()
	if err := b.Set(context.Background(), "k", buf); !errors.Is(err, ErrBackendReadOnly) {
		t.Fatalf("Set: want ErrBackendReadOnly, got %v", err)
	}
	if err := b.Delete(context.Background(), "k"); !errors.Is(err, ErrBackendReadOnly) {
		t.Fatalf("Delete: want ErrBackendReadOnly, got %v", err)
	}
	if sanitizeBackendErr(b.Set(context.Background(), "k", buf)) != "read_only" {
		t.Fatal("read-only error should sanitize to read_only token")
	}
}

// TestExecProtonRunner_DropsStderr verifies the real runner discards pass-cli
// stderr (which can echo item data) and names only the subcommand in its error.
func TestExecProtonRunner_DropsStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-pass-cli")
	body := "#!/bin/sh\necho STDERRSECRET 1>&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := execProtonRunner(context.Background(), script, "item", "view")
	if err == nil {
		t.Fatal("want error on exit 1")
	}
	if strings.Contains(err.Error(), "STDERRSECRET") {
		t.Fatalf("error leaked pass-cli stderr: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "item view") {
		t.Fatalf("error should name the subcommand: %q", err.Error())
	}
}
