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

// metaKeyPrefix namespaces a secret's companion policy item. A valid secret
// name can't contain '/', so a "meta/" key never collides with a real secret.
// Callers enumerating keys must account for it: the CLI shows these as status,
// but list_secrets MUST filter them (isMetaKey) so the AI never sees the scheme
// or a revoked tombstone.
const metaKeyPrefix = "meta/"

// secretMetaVersion stamps each SecretMeta; bump only on an incompatible
// JSON-shape change.
const secretMetaVersion = 1

func metaKey(name string) string { return metaKeyPrefix + name }

func isMetaKey(key string) bool { return strings.HasPrefix(key, metaKeyPrefix) }

func secretNameFromMetaKey(key string) (string, bool) {
	if !isMetaKey(key) {
		return "", false
	}
	return key[len(metaKeyPrefix):], true
}

// ErrSecretExpired and ErrSecretRevoked are distinct from ErrSecretNotFound so
// the read paths can report a precise audit taxonomy.
var (
	ErrSecretExpired = errors.New("secret has expired")
	ErrSecretRevoked = errors.New("secret has been revoked")
)

// SecretMeta is a secret's policy, stored as a companion keyring item. Times are
// UTC; a zero time means unset. It rides the encrypted keyring (not a sidecar)
// so it is co-located with, and as tamper-resistant as, the secret it governs.
type SecretMeta struct {
	V         int       `json:"v"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// IsRevoked reports a revocation tombstone. Nil-safe (no metadata = no policy).
func (m *SecretMeta) IsRevoked() bool { return m != nil && !m.RevokedAt.IsZero() }

// HasExpiry reports whether a TTL is set. Nil-safe.
func (m *SecretMeta) HasExpiry() bool { return m != nil && !m.ExpiresAt.IsZero() }

// IsExpiredAt reports whether the TTL has lapsed; the boundary is inclusive
// (now == ExpiresAt is expired). Nil-safe.
func (m *SecretMeta) IsExpiredAt(now time.Time) bool {
	return m.HasExpiry() && !now.Before(m.ExpiresAt)
}

// loadMeta returns (nil, nil) when a secret has no companion item (legacy and
// policy-free secrets alike), so callers treat nil as "no policy" (the nil-safe
// methods above make that ergonomic).
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

// storeMeta writes m to the companion item. The JSON is not secret, but it
// reuses the locked-Buffer storage path to avoid a second write path.
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

// deleteMeta is idempotent (a missing item is not an error) so the set and
// delete paths can call it unconditionally to clear any prior policy or
// tombstone.
func deleteMeta(ctx context.Context, backend Backend, name string) error {
	err := backend.Delete(ctx, metaKey(name))
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	return err
}

// resolveSecret is the single read path for plaintext secret values, so TTL and
// revocation are enforced everywhere a value could escape. It never mutates the
// keyring: expiry only refuses; wiping is left to revoke/prune. Revoked is
// checked before expired so a deliberately-killed secret reports the precise
// ErrSecretRevoked.
func resolveSecret(ctx context.Context, backend Backend, name string, now time.Time) (*Buffer, error) {
	// Defense in depth: a valid name can't contain '/', so it can't reach the
	// meta/ namespace. Re-checking here stops a future caller that skips the
	// guard from turning this into a namespace-confusion primitive.
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

// filterVisibleSecretNames drops companion meta/ keys from a raw listing. The
// MCP list_secrets tool MUST use it so the AI never sees the scheme or a revoked
// secret's surviving tombstone.
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

// sanitizePolicyErr maps a resolveSecret error to a stable audit token,
// extending sanitizeBackendErr with the policy outcomes. Tokens are bare (no
// '=') so they pass the AI-visible message allowlist like the other taxonomy.
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

// parseTTL accepts Go durations plus "d"/"w" units, which time.ParseDuration
// lacks; fractional values are allowed ("0.5d"). Must be strictly positive.
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
			// Bound-check in float64 before the int64 conversion: time.Duration
			// of an out-of-range float wraps, which could pass a <=0 check and
			// make now.Add overflow into the past. Also rejects ParseFloat's
			// nan/inf.
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
