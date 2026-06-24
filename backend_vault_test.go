package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// fakeVault is an in-memory KV v2 endpoint for exercising vaultBackend without a
// real Vault. It models the v2 path scheme (/data/ for values, /metadata/ for
// list + destroy) and the non-recursive LIST that returns subdir markers.
type fakeVault struct {
	store      map[string][]byte // opq key (may contain "/") -> raw value bytes
	requests   []string          // "METHOD path" log for assertions
	gotToken   string
	gotNS      string
	failStatus map[string]int // HTTP method -> status to fail that request with (0/absent = succeed)
}

const fakeMount = "secret"
const fakePrefix = "opq"

func newFakeVaultBackend(t *testing.T) (*vaultBackend, *fakeVault) {
	t.Helper()
	fv := &fakeVault{store: map[string][]byte{}}
	dataPre := "/v1/" + fakeMount + "/data/" + fakePrefix
	metaPre := "/v1/" + fakeMount + "/metadata/" + fakePrefix

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fv.requests = append(fv.requests, r.Method+" "+r.URL.Path)
		fv.gotToken = r.Header.Get("X-Vault-Token")
		fv.gotNS = r.Header.Get("X-Vault-Namespace")
		if code := fv.failStatus[r.Method]; code != 0 {
			http.Error(w, `{"errors":["boom"]}`, code)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, dataPre):
			fv.serveData(w, r, keyFromPath(r.URL.Path, dataPre))
		case strings.HasPrefix(r.URL.Path, metaPre):
			if r.URL.Query().Get("list") == "true" {
				fv.serveList(w, dirFromPath(r.URL.Path, metaPre))
				return
			}
			fv.serveMeta(w, r, keyFromPath(r.URL.Path, metaPre))
		default:
			http.Error(w, "unexpected path", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	return &vaultBackend{
		addr:      srv.URL,
		token:     "test-token",
		namespace: "ns1",
		mount:     fakeMount,
		prefix:    fakePrefix,
		hc:        srv.Client(),
	}, fv
}

func keyFromPath(path, prefix string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, prefix), "/")
}

func dirFromPath(path, prefix string) string {
	return strings.TrimPrefix(strings.TrimPrefix(path, prefix), "/") // "" or "meta"
}

func (fv *fakeVault) serveData(w http.ResponseWriter, r *http.Request, key string) {
	switch r.Method {
	case http.MethodGet:
		v, ok := fv.store[key]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{
			"data": map[string]any{
				"data": map[string]string{vaultValueField: base64.StdEncoding.EncodeToString(v)},
			},
		})
	case http.MethodPost:
		var req struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		dec, err := base64.StdEncoding.DecodeString(req.Data[vaultValueField])
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
		fv.store[key] = dec
		writeJSON(w, map[string]any{"data": map[string]any{"version": 1}})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (fv *fakeVault) serveMeta(w http.ResponseWriter, r *http.Request, key string) {
	switch r.Method {
	case http.MethodGet: // existence probe used by Delete
		if _, ok := fv.store[key]; !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"current_version": 1}})
	case http.MethodDelete: // destroy all versions (idempotent in real Vault)
		delete(fv.store, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

// serveList mirrors KV v2's non-recursive LIST: returns immediate children of
// the directory, with subdirectories suffixed "/". A directory with no children
// 404s (as real Vault does for a never-written path).
func (fv *fakeVault) serveList(w http.ResponseWriter, dir string) {
	set := map[string]bool{}
	if dir == "" {
		for k := range fv.store {
			if i := strings.IndexByte(k, '/'); i >= 0 {
				set[k[:i+1]] = true // "meta/" folder marker
			} else {
				set[k] = true
			}
		}
	} else {
		pre := dir + "/"
		for k := range fv.store {
			if strings.HasPrefix(k, pre) {
				set[k[len(pre):]] = true
			}
		}
	}
	if len(set) == 0 {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		return
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeJSON(w, map[string]any{"data": map[string]any{"keys": keys}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func getBackendValue(t *testing.T, b Backend, name string) string {
	t.Helper()
	buf, err := b.Get(context.Background(), name)
	if err != nil {
		t.Fatalf("Get(%q): %v", name, err)
	}
	defer buf.Destroy()
	return string(buf.Bytes())
}

func TestOpenVaultBackend_RequiresHTTPS(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "tok")
	t.Setenv("OPQ_VAULT_ALLOW_INSECURE_HTTP", "")

	// Plaintext http is rejected by default (the token + values would cross the
	// wire in the clear).
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	if _, err := openVaultBackend(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http without opt-in must be rejected, got %v", err)
	}

	// ...but allowed behind the explicit opt-in (e.g. a localhost dev server).
	t.Setenv("OPQ_VAULT_ALLOW_INSECURE_HTTP", "1")
	if _, err := openVaultBackend(); err != nil {
		t.Fatalf("http with opt-in should be allowed, got %v", err)
	}
	t.Setenv("OPQ_VAULT_ALLOW_INSECURE_HTTP", "")

	// https is always accepted.
	t.Setenv("VAULT_ADDR", "https://vault.example:8200")
	if _, err := openVaultBackend(); err != nil {
		t.Fatalf("https should be allowed, got %v", err)
	}

	// A non-absolute URL is rejected.
	t.Setenv("VAULT_ADDR", "not-a-url")
	if _, err := openVaultBackend(); err == nil || !strings.Contains(err.Error(), "absolute URL") {
		t.Fatalf("non-URL VAULT_ADDR must be rejected, got %v", err)
	}
}

func TestVaultBackend_RoundTrip(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	mustSet(t, b, "github_token", "ghp_abc123")
	if got := getBackendValue(t, b, "github_token"); got != "ghp_abc123" {
		t.Fatalf("round-trip: got %q", got)
	}
}

func TestVaultBackend_BinaryValueRoundTrips(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	// Every non-NUL byte (NUL is rejected at the Buffer constructor, not here).
	raw := make([]byte, 0, 255)
	for i := 1; i <= 255; i++ {
		raw = append(raw, byte(i))
	}
	buf, err := NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	if err := b.Set(context.Background(), "bin", buf); err != nil {
		buf.Destroy()
		t.Fatalf("Set: %v", err)
	}
	buf.Destroy()

	got, err := b.Get(context.Background(), "bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer got.Destroy()
	if string(got.Bytes()) != string(raw) {
		t.Fatalf("binary round-trip mismatch: got %d bytes", got.Size())
	}
}

func TestVaultBackend_GetNotFound(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	if _, err := b.Get(context.Background(), "missing"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(missing): want ErrSecretNotFound, got %v", err)
	}
}

func TestVaultBackend_DeleteUsesMetadataPath(t *testing.T) {
	b, fv := newFakeVaultBackend(t)
	mustSet(t, b, "tok", "v")
	if err := b.Delete(context.Background(), "tok"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(context.Background(), "tok"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("after Delete, Get: want ErrSecretNotFound, got %v", err)
	}
	// The destroy must target /metadata/ (hard wipe of all versions), never the
	// soft /data/ delete.
	sawMetaDelete := false
	for _, req := range fv.requests {
		if strings.HasPrefix(req, "DELETE ") {
			if !strings.Contains(req, "/metadata/") {
				t.Fatalf("Delete hit a non-metadata path: %q", req)
			}
			sawMetaDelete = true
		}
	}
	if !sawMetaDelete {
		t.Fatal("no DELETE request recorded")
	}
}

func TestVaultBackend_DeleteMissing(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	if err := b.Delete(context.Background(), "nope"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Delete(missing): want ErrSecretNotFound, got %v", err)
	}
}

func TestVaultBackend_ListReconstruction(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	mustSet(t, b, "github_token", "a")
	mustSet(t, b, "aws_key", "b")
	mustSet(t, b, "meta/github_token", `{"v":1}`)

	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"aws_key", "github_token", "meta/github_token"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("List: got %v want %v", keys, want)
	}
	for _, k := range keys {
		if k == metaKeyPrefix {
			t.Fatal("List leaked a bare meta/ folder marker")
		}
	}
}

func TestVaultBackend_ListEmptyMount(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	keys, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List on empty mount: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List on empty mount: want empty, got %v", keys)
	}
}

func TestVaultBackend_SendsAuthHeaders(t *testing.T) {
	b, fv := newFakeVaultBackend(t)
	mustSet(t, b, "tok", "v")
	if fv.gotToken != "test-token" {
		t.Fatalf("X-Vault-Token: got %q", fv.gotToken)
	}
	if fv.gotNS != "ns1" {
		t.Fatalf("X-Vault-Namespace: got %q", fv.gotNS)
	}
}

func TestVaultBackend_ErrorOmitsTokenAndBody(t *testing.T) {
	b, fv := newFakeVaultBackend(t)
	fv.failStatus = map[string]int{http.MethodGet: http.StatusForbidden}
	_, err := b.Get(context.Background(), "x")
	assertVaultErrStatusOnly(t, err, "403")
}

// assertVaultErrStatusOnly checks the status-code-only error policy: the error
// carries the status but never the token or the response body, and sanitizes to
// the generic backend_error audit token.
func assertVaultErrStatusOnly(t *testing.T, err error, status string) {
	t.Helper()
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if strings.Contains(msg, "test-token") {
		t.Fatalf("error leaked the token: %q", msg)
	}
	if strings.Contains(msg, "boom") {
		t.Fatalf("error leaked the response body: %q", msg)
	}
	if !strings.Contains(msg, status) {
		t.Fatalf("error should carry status %s: %q", status, msg)
	}
	if sanitizeBackendErr(err) != "backend_error" {
		t.Fatalf("sanitizeBackendErr: got %q", sanitizeBackendErr(err))
	}
}

// TestVaultBackend_DeleteDestroyFails covers the destroy branch of the two-call
// Delete (existence probe succeeds, the metadata destroy returns non-2xx).
func TestVaultBackend_DeleteDestroyFails(t *testing.T) {
	b, fv := newFakeVaultBackend(t)
	mustSet(t, b, "tok", "v") // probe GET will find it
	fv.failStatus = map[string]int{http.MethodDelete: http.StatusForbidden}
	assertVaultErrStatusOnly(t, b.Delete(context.Background(), "tok"), "403")
}

// TestVaultBackend_SetStatusError covers Set's non-2xx branch.
func TestVaultBackend_SetStatusError(t *testing.T) {
	b, fv := newFakeVaultBackend(t)
	fv.failStatus = map[string]int{http.MethodPost: http.StatusInternalServerError}
	buf, _ := NewBufferFromBytes([]byte("v"))
	defer buf.Destroy()
	assertVaultErrStatusOnly(t, b.Set(context.Background(), "tok", buf), "500")
}
