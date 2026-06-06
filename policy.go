package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// metaKeyPrefix namespaces companion metadata items inside the keyring. A
// valid secret name matches validSecretName ([A-Za-z0-9_.-]{1,128}), which can
// never contain '/', so a "meta/"-prefixed key cannot collide with any secret
// the operator is able to store. Metadata rides the same encrypted keyring as
// the secret it describes (Alex's chosen storage model) — it is co-located,
// backed up together, and tamper-resistant to the same degree as the secret.
//
// Because metadata items share the keyring keyspace with secrets, every code
// path that enumerates keys for a CALLER (CLI `list`, MCP `list_secrets`) must
// account for the prefix: the CLI surfaces them as policy status, the MCP tool
// MUST filter them out (isMetaKey) so the AI never sees the internal scheme.
const metaKeyPrefix = "meta/"

// secretMetaVersion is the schema version stamped into every SecretMeta we
// write. Bumped only on an incompatible JSON-shape change; loadMeta tolerates
// older versions by virtue of json's permissive field matching.
const secretMetaVersion = 1

func metaKey(name string) string { return metaKeyPrefix + name }

// isMetaKey reports whether a raw keyring key is a companion metadata item
// rather than a secret. Used by callers that enumerate keys to keep the two
// keyspaces separate.
func isMetaKey(key string) bool { return strings.HasPrefix(key, metaKeyPrefix) }

// secretNameFromMetaKey returns the secret name a metadata key describes, and
// whether the key was in fact a metadata key.
func secretNameFromMetaKey(key string) (string, bool) {
	if !isMetaKey(key) {
		return "", false
	}
	return key[len(metaKeyPrefix):], true
}

// ErrSecretExpired / ErrSecretRevoked are returned by resolveSecret when a
// secret's policy metadata forbids returning its value. They are distinct from
// ErrSecretNotFound so call sites can emit a precise audit taxonomy and a
// precise caller-facing error.
var (
	ErrSecretExpired = errors.New("secret has expired")
	ErrSecretRevoked = errors.New("secret has been revoked")
)

// SecretMeta is the policy envelope stored in a companion keyring item next to
// a secret. All times are UTC; a zero time means "unset". The struct is JSON
// serialized and stored through the ordinary Backend.Set path (wrapped in a
// Buffer) — it is not itself secret, but living in the encrypted keyring keeps
// it co-located with and as tamper-resistant as the secret it governs.
type SecretMeta struct {
	V         int       `json:"v"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// IsRevoked reports whether the secret carries a revocation tombstone. Safe on
// a nil receiver (a secret with no metadata has no policy).
func (m *SecretMeta) IsRevoked() bool { return m != nil && !m.RevokedAt.IsZero() }

// HasExpiry reports whether the secret has a TTL set at all.
func (m *SecretMeta) HasExpiry() bool { return m != nil && !m.ExpiresAt.IsZero() }

// IsExpiredAt reports whether the secret's TTL has lapsed as of now. The
// boundary is inclusive: a secret whose ExpiresAt equals now is expired. Safe
// on a nil receiver.
func (m *SecretMeta) IsExpiredAt(now time.Time) bool {
	return m.HasExpiry() && !now.Before(m.ExpiresAt)
}

// loadMeta fetches and parses a secret's companion metadata. Returns
// (nil, nil) when no metadata item exists — legacy secrets stored before this
// feature, and any secret the keyring holds without a policy. Callers treat a
// nil meta as "no policy" (the nil-receiver methods above make that ergonomic).
func loadMeta(ctx context.Context, backend Backend, name string) (*SecretMeta, error) {
	buf, err := backend.Get(ctx, metaKey(name))
	if errors.Is(err, ErrSecretNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	var m SecretMeta
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return nil, fmt.Errorf("parse secret metadata for %q: %w", name, err)
	}
	return &m, nil
}

// storeMeta serializes m and writes it to the companion keyring item. The
// metadata JSON is routed through the same locked-Buffer path as a secret so
// it never lingers on the heap; the bytes are not actually secret, but reusing
// one storage path keeps the code surface small.
func storeMeta(ctx context.Context, backend Backend, name string, m *SecretMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal secret metadata: %w", err)
	}
	buf, err := NewBufferFromBytes(raw) // copies into locked buffer, wipes raw
	if err != nil {
		return fmt.Errorf("buffer secret metadata: %w", err)
	}
	defer buf.Destroy()
	return backend.Set(ctx, metaKey(name), buf)
}

// deleteMeta removes a secret's companion metadata item. A missing item is not
// an error — deleteMeta is idempotent so the set/delete paths can call it
// unconditionally to clear any stale policy (including a revoked tombstone).
func deleteMeta(ctx context.Context, backend Backend, name string) error {
	err := backend.Delete(ctx, metaKey(name))
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	return err
}

// resolveSecret is the single read path for secret VALUES (cmd_get, cmd_exec,
// MCP run_with_secrets) so TTL and revocation are enforced uniformly wherever a
// plaintext value would otherwise be handed out.
//
// The check is READ-ONLY: an expired or revoked secret is refused but never
// mutated here. Destruction is an explicit operator action — `opq revoke` wipes
// the value eagerly and `opq prune` sweeps lapsed TTLs — keeping the hot read
// path free of keyring writes (Alex's chosen invariant for the first cut).
//
// Order matters: revoked beats expired beats fetch. A revoked secret has had
// its value wiped already (revoke deletes the secret item and leaves only the
// tombstone), so checking IsRevoked first means backend.Get is never even
// attempted and the caller gets the precise ErrSecretRevoked rather than a
// generic not-found.
func resolveSecret(ctx context.Context, backend Backend, name string, now time.Time) (*Buffer, error) {
	// Defense in depth: every current caller already runs validSecretName, and
	// a valid name cannot contain '/', so it can never address the "meta/"
	// namespace. Re-checking here means a future caller that forgets the guard
	// still cannot turn resolveSecret into a namespace-confusion primitive — an
	// invalid name simply cannot exist, so we fail closed as not-found.
	if !validSecretName(name) {
		return nil, ErrSecretNotFound
	}
	meta, err := loadMeta(ctx, backend, name)
	if err != nil {
		return nil, err
	}
	if meta.IsRevoked() {
		return nil, ErrSecretRevoked
	}
	if meta.IsExpiredAt(now) {
		return nil, ErrSecretExpired
	}
	return backend.Get(ctx, name)
}

// filterVisibleSecretNames drops companion metadata keys from a raw keyring
// listing, returning only the secret names a caller should see. The MCP
// list_secrets tool MUST route through this so the internal "meta/" scheme —
// and any revoked secret's surviving tombstone — never reaches the AI.
func filterVisibleSecretNames(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if isMetaKey(k) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// sanitizePolicyErr maps a resolveSecret error to a stable, side-channel-free
// audit token. It extends sanitizeBackendErr with the policy outcomes so the
// get/exec/MCP read paths emit a precise taxonomy (secret_revoked /
// secret_expired / not_found / backend_error) without leaking raw error text.
// The tokens are bare (no '='), so they bypass the AI-visible message
// allowlist by the same rule as env_blocked / invalid_secret_name.
func sanitizePolicyErr(err error) string {
	switch {
	case errors.Is(err, ErrSecretRevoked):
		return "secret_revoked"
	case errors.Is(err, ErrSecretExpired):
		return "secret_expired"
	default:
		return sanitizeBackendErr(err)
	}
}

// parseTTL parses a TTL duration string. It extends Go's time.ParseDuration
// with day ("d") and week ("w") units — natural for secret lifetimes but
// unsupported by the stdlib, which stops at hours. A plain Go duration ("24h",
// "90m", "1h30m") still works. Fractional day/week values are allowed ("0.5d"
// → 12h). The result must be strictly positive.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty ttl")
	}
	if n := len(s); n >= 2 {
		switch s[n-1] {
		case 'd', 'w':
			num, err := strconv.ParseFloat(s[:n-1], 64)
			if err != nil {
				return 0, fmt.Errorf("invalid ttl %q (use forms like 24h, 90m, 7d, 2w)", s)
			}
			base := 24 * time.Hour
			if s[n-1] == 'w' {
				base = 7 * 24 * time.Hour
			}
			// Compute in float64 and bound-check BEFORE the int64 conversion:
			// time.Duration(huge_float) is implementation-defined and wraps,
			// which could yield a tiny/negative duration that slips past a
			// post-conversion <=0 check and makes now.Add(ttl) overflow into the
			// past. Rejecting NaN/Inf also covers ParseFloat accepting "nan"/"inf".
			ns := num * float64(base)
			if math.IsNaN(ns) || math.IsInf(ns, 0) || ns <= 0 {
				return 0, fmt.Errorf("ttl must be positive: %q", s)
			}
			if ns >= float64(math.MaxInt64) {
				return 0, fmt.Errorf("ttl %q is too large (max ~292 years)", s)
			}
			return time.Duration(ns), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q (use forms like 24h, 90m, 7d, 2w)", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive: %q", s)
	}
	return d, nil
}
