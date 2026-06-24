package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/awnumar/memguard"
)

// vaultBackend is a thin HashiCorp Vault KV v2 client implementing Backend over
// net/http (no hashicorp/vault/api SDK, to keep the dependency tree lean and
// govulncheck-able). It treats every stored value as opaque bytes, so opq's
// real secrets and their companion meta/<name> policy items both round-trip
// with no special-casing.
//
// The mount MUST be a KV v2 mount: the /data/ + /metadata/ path scheme and the
// nested data.data envelope are v2-specific. A KV v1 mount would 404.
type vaultBackend struct {
	addr      string // VAULT_ADDR, trailing slash trimmed
	token     string // VAULT_TOKEN
	namespace string // VAULT_NAMESPACE (optional; X-Vault-Namespace header)
	mount     string // OPQ_VAULT_MOUNT,  default "secret"
	prefix    string // OPQ_VAULT_PREFIX, default "opq"
	hc        *http.Client
}

// vaultValueField is the single KV v2 data field opq stores the (base64'd)
// secret bytes under. Keeping it fixed means the backend never has to interpret
// the value, only carry it.
const vaultValueField = "value"

// maxVaultResponse bounds how much of a Vault response body we read; KV v2
// responses are small, so this only guards against a pathological/hostile peer.
const maxVaultResponse = 1 << 20 // 1 MiB

func openVaultBackend() (Backend, error) {
	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return nil, errors.New("vault backend requires VAULT_ADDR and VAULT_TOKEN")
	}
	// Require HTTPS by default: over plaintext http the X-Vault-Token header and
	// the base64-wrapped secret values cross the network in the clear (a
	// first-request leak the CheckRedirect guard below cannot help with). Allow
	// http only behind an explicit opt-in (e.g. a localhost dev server).
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return nil, errors.New("vault backend requires VAULT_ADDR to be an absolute URL")
	}
	if u.Scheme != "https" && os.Getenv("OPQ_VAULT_ALLOW_INSECURE_HTTP") != "1" {
		return nil, errors.New("vault backend requires an https VAULT_ADDR (set OPQ_VAULT_ALLOW_INSECURE_HTTP=1 to allow plaintext http)")
	}
	prefix := strings.Trim(envOr("OPQ_VAULT_PREFIX", "opq"), "/")
	if prefix == "" {
		// An empty prefix would scope opq to the entire mount root, surprising
		// the operator by listing/managing unrelated secrets. Keep a namespace.
		prefix = "opq"
	}
	return &vaultBackend{
		addr:      addr,
		token:     token,
		namespace: os.Getenv("VAULT_NAMESPACE"),
		mount:     strings.Trim(envOr("OPQ_VAULT_MOUNT", "secret"), "/"),
		prefix:    prefix,
		hc: &http.Client{
			Timeout: 15 * time.Second,
			// Never chase a 3xx: Go re-sends the custom X-Vault-Token header on
			// every redirect hop (it only strips Authorization/Cookie), so a
			// redirect to another host would hand the token to that host. A KV
			// path returns 2xx directly; surface a 3xx as a status-only error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (b *vaultBackend) Name() string { return "vault" }

// envOr returns the env var value or a default when unset/empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// keyPath joins the configured prefix with an opq key, path-escaping each key
// segment. The only '/' a valid key can contain is the meta/ separator
// (validate.go forbids '/' in a real secret name), so this yields at most
// prefix/meta/<name>. The prefix is operator config (may itself be a nested
// path) and is left unescaped.
func (b *vaultBackend) keyPath(key string) string {
	segs := make([]string, 0, 3)
	if b.prefix != "" {
		segs = append(segs, b.prefix)
	}
	for s := range strings.SplitSeq(key, "/") {
		segs = append(segs, url.PathEscape(s))
	}
	return strings.Join(segs, "/")
}

func (b *vaultBackend) dataURL(key string) string {
	return b.addr + "/v1/" + b.mount + "/data/" + b.keyPath(key)
}

func (b *vaultBackend) metaURL(key string) string {
	return b.addr + "/v1/" + b.mount + "/metadata/" + b.keyPath(key)
}

// listURL builds a KV v2 metadata LIST URL for the prefix directory (sub == "")
// or a sub-directory of it (e.g. sub == "meta"). We use GET ...?list=true
// rather than the custom LIST verb so any plain HTTP proxy in front of Vault
// passes it through.
func (b *vaultBackend) listURL(sub string) string {
	dir := b.prefix
	if sub != "" {
		if dir != "" {
			dir += "/"
		}
		dir += sub
	}
	return b.addr + "/v1/" + b.mount + "/metadata/" + dir + "?list=true"
}

// do issues a single Vault request and returns the status, the (bounded) body,
// and a transport error. It never returns the response body or token inside the
// error: HTTP failures are reported as status codes only, so no Vault-supplied
// bytes can reach the audit log or operator stderr.
func (b *vaultBackend) do(ctx context.Context, method, u string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("vault: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", b.token)
	if b.namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		// The transport error may carry the URL (mount/prefix/key NAME, never
		// the value) but not the token (headers are not in url.Error); it aids
		// operator debugging and is sanitized to "backend_error" for the audit.
		return 0, nil, fmt.Errorf("vault: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxVaultResponse))
	return resp.StatusCode, respBody, nil
}

type vaultReadResp struct {
	Data struct {
		Data struct {
			// encoding/json base64-decodes the KV v2 "value" string straight
			// into this []byte, so neither the raw secret nor its base64 form
			// ever lands in an unwipeable Go string in our code. (Field tag is
			// the literal "value"; cf. vaultValueField used to build the body.)
			Value []byte `json:"value"`
		} `json:"data"`
	} `json:"data"`
}

type vaultListResp struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

func (b *vaultBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	status, body, err := b.do(ctx, http.MethodGet, b.dataURL(name), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrSecretNotFound
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("vault get: status %d", status)
	}
	defer memguard.WipeBytes(body)

	var r vaultReadResp
	if err := json.Unmarshal(body, &r); err != nil {
		// A non-base64 "value" (a foreign entry at our path) also lands here.
		return nil, errors.New("vault get: parse response")
	}
	val := r.Data.Data.Value
	if len(val) == 0 {
		// Present but not an opq value (foreign entry, or value field absent):
		// from opq's perspective there is nothing to return.
		return nil, ErrSecretNotFound
	}
	buf, err := NewBufferFromBytes(val) // copies into a locked buffer, wipes val
	if err != nil {
		return nil, fmt.Errorf("vault get: %w", err)
	}
	return buf, nil
}

func (b *vaultBackend) Set(ctx context.Context, name string, value *Buffer) error {
	if value == nil || !value.IsAlive() {
		return errors.New("vault set: empty value")
	}
	raw := value.Bytes()
	// base64 into a buffer we own so we can wipe it; the encoded form of a
	// secret is itself sensitive. base64-std uses only [A-Za-z0-9+/=], all of
	// which are JSON-safe, so we hand-build the body and avoid an unwipeable
	// string copy through json.Marshal.
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, raw)
	defer memguard.WipeBytes(enc)

	body := make([]byte, 0, len(enc)+24)
	body = append(body, `{"data":{"`...)
	body = append(body, vaultValueField...)
	body = append(body, `":"`...)
	body = append(body, enc...)
	body = append(body, `"}}`...)
	defer memguard.WipeBytes(body)

	status, _, err := b.do(ctx, http.MethodPost, b.dataURL(name), body)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("vault set: status %d", status)
	}
	return nil
}

func (b *vaultBackend) Delete(ctx context.Context, name string) error {
	// DELETE on the metadata path destroys ALL versions + metadata (a true
	// wipe, matching revoke/prune semantics) — NOT the soft DELETE on /data/,
	// which leaves recoverable versions. But Vault's metadata DELETE is
	// idempotent (204 even for a missing key), while the Backend contract
	// requires ErrSecretNotFound for misses (cmd_delete / cmd_revoke branch on
	// it), so probe existence first. The TOCTOU window only risks a harmless
	// redundant destroy.
	status, _, err := b.do(ctx, http.MethodGet, b.metaURL(name), nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return ErrSecretNotFound
	}
	if status/100 != 2 {
		return fmt.Errorf("vault delete: status %d", status)
	}
	dstatus, _, err := b.do(ctx, http.MethodDelete, b.metaURL(name), nil)
	if err != nil {
		return err
	}
	if dstatus/100 != 2 {
		return fmt.Errorf("vault delete: status %d", dstatus)
	}
	return nil
}

// List reconstructs opq's flat keyspace from KV v2's non-recursive LIST. The
// top-level listing returns real secret names plus a "meta/" subdirectory
// marker; we expand that marker by listing the meta/ folder and re-prefixing
// its entries, so callers see e.g. ["aws_key", "github_token",
// "meta/github_token"] exactly as the keyring backend would.
func (b *vaultBackend) List(ctx context.Context) ([]string, error) {
	top, err := b.listDir(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(top))
	metaPresent := false
	for _, k := range top {
		if k == metaKeyPrefix { // "meta/" folder marker
			metaPresent = true
			continue
		}
		if strings.HasSuffix(k, "/") {
			continue // opq's keyspace is flat; ignore any other subdirectory
		}
		out = append(out, k)
	}
	if metaPresent {
		metas, err := b.listDir(ctx, "meta")
		if err != nil {
			return nil, err
		}
		for _, mk := range metas {
			if strings.HasSuffix(mk, "/") {
				continue
			}
			out = append(out, metaKeyPrefix+mk)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (b *vaultBackend) listDir(ctx context.Context, sub string) ([]string, error) {
	status, body, err := b.do(ctx, http.MethodGet, b.listURL(sub), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil // empty/absent path -> no keys, not an error
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("vault list: status %d", status)
	}
	var r vaultListResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errors.New("vault list: parse response")
	}
	return r.Data.Keys, nil
}
