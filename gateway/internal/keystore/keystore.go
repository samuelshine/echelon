// Package keystore provides a mutable API-key store: keys can be created,
// re-limited, and revoked at runtime (unlike auth.StaticAPIKeyAuthenticator,
// which is frozen at boot). Two implementations mirror the memory/Postgres split
// used by internal/ratelimit, internal/credit, and internal/telemetry:
//
//   - MemoryStore  — mutex-protected, in-process, zero external dependencies.
//   - PostgresStore — pgxpool-backed, survives restarts.
//
// Both satisfy ports.Authenticator via Authenticate, so the store is the single
// source of truth for both the console's key-management UI and request auth.
package keystore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/jscyril/echelon/internal/core"
)

// Key is privacy-safe API-key metadata. It deliberately never carries the
// plaintext secret or its digest — only the last four characters are retained
// for display, matching the console's `sk_live_••••••••<last4>` convention.
type Key struct {
	ID           string
	Label        string
	Last4        string
	CreatedAt    string // RFC3339
	Status       string // "active" | "revoked"
	RateLimitRpm int
	CreditBudget int64
}

// Store is the mutable API-key store. Authenticate satisfies ports.Authenticator.
type Store interface {
	List(ctx context.Context) ([]Key, error)
	Create(ctx context.Context, label string, rateLimitRpm int, creditBudget int64) (key Key, secret string, err error)
	UpdateLimits(ctx context.Context, id string, rateLimitRpm int, creditBudget int64) (Key, error)
	Revoke(ctx context.Context, id string) (Key, error)
	Authenticate(ctx context.Context, credential string) (core.Identity, error)
}

// ErrNotFound is returned by UpdateLimits/Revoke for an unknown id, letting the
// gateway map it to a 404 without string-matching.
var ErrNotFound = fmt.Errorf("api key not found")

// Defaults for a freshly-created console key. They match the values
// buildConsoleKeys/buildCreditSeed used for seeded keys so create/list are
// visually consistent.
const (
	DefaultRateLimitRpm = 1000
	DefaultCreditBudget = 100_000
)

// SeedKey is one bootstrap key parsed from ECHELON_API_KEYS: its plaintext
// secret, display metadata, and the identity Authenticate should return. The
// MemoryStore honors Identity verbatim (preserving the exact legacy tenant/
// keyid/plan for the zero-Postgres dev path); the PostgresStore has no tenant
// column and so derives Identity from the stored id — see identityFor.
type SeedKey struct {
	Secret   string
	Key      Key
	Identity core.Identity
}

// generateSecret mints `sk_live_` + 32 lowercase-hex chars from crypto/rand,
// matching the format the (now-removed) client-side generateSecret() used, so
// the console's reveal/display UX keeps working unchanged.
func generateSecret() (secret, last4 string) {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	body := hex.EncodeToString(buf) // 32 lowercase-hex chars
	return "sk_live_" + body, body[len(body)-4:]
}

// generateID mints a stable, unique id for a newly-created key.
func generateID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "key_" + hex.EncodeToString(buf)
}

// digestHex is the hex-encoded SHA-256 of a plaintext secret — the form stored
// in Postgres and indexed for Authenticate's lookup. Plaintext is never stored.
func digestHex(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// identityFor is the per-key tenancy rule for created keys and for all
// PostgresStore keys: each key is its own tenant. The console UI edits
// creditBudget/rateLimitRpm per-key (not per-tenant), so per-key tenancy is what
// the UI actually models; the legacy static multi-key-per-tenant grouping was
// never surfaced anywhere real.
func identityFor(id string) core.Identity {
	return core.Identity{TenantID: id, APIKeyID: id}
}
