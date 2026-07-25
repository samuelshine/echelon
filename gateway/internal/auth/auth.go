// Package auth provides API-key authentication with constant-time comparison.
// Keys are matched against stored SHA-256 digests so plaintext keys are not held
// in memory longer than needed and comparisons do not leak timing information.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/jscyril/echelon/internal/core"
)

var ErrUnauthorized = fmt.Errorf("unauthorized")

type entry struct {
	digest   [32]byte
	identity core.Identity
}

// StaticAPIKeyAuthenticator authenticates bearer credentials against a fixed set
// of API keys. It satisfies ports.Authenticator and is safe for concurrent use
// after construction (immutable).
type StaticAPIKeyAuthenticator struct {
	entries []entry
}

// NewStaticAPIKeyAuthenticator builds an authenticator from plaintext key ->
// identity. Plaintext is hashed immediately and not retained.
func NewStaticAPIKeyAuthenticator(keys map[string]core.Identity) (*StaticAPIKeyAuthenticator, error) {
	entries := make([]entry, 0, len(keys))
	for key, identity := range keys {
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("api key must be non-empty")
		}
		entries = append(entries, entry{digest: sha256.Sum256([]byte(key)), identity: identity})
	}
	return &StaticAPIKeyAuthenticator{entries: entries}, nil
}

// Authenticate returns the identity for a credential, or ErrUnauthorized. It
// compares against every entry in constant time so a caller cannot learn which
// (if any) key prefix matched from timing.
func (a *StaticAPIKeyAuthenticator) Authenticate(_ context.Context, credential string) (core.Identity, error) {
	credential = strings.TrimSpace(strings.TrimPrefix(credential, "Bearer "))
	if credential == "" {
		return core.Identity{}, ErrUnauthorized
	}
	candidate := sha256.Sum256([]byte(credential))
	var matched core.Identity
	found := 0
	for i := range a.entries {
		if subtle.ConstantTimeCompare(candidate[:], a.entries[i].digest[:]) == 1 {
			matched = a.entries[i].identity
			found = 1
		}
	}
	if found == 0 {
		return core.Identity{}, ErrUnauthorized
	}
	return matched, nil
}
