package keystore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/core"
)

// memEntry is one stored key: its digest (for constant-time comparison), its
// display metadata, and the identity Authenticate returns.
type memEntry struct {
	digest   [32]byte
	key      Key
	identity core.Identity
}

// MemoryStore is a mutex-protected, in-process API-key store. It is seeded from
// ECHELON_API_KEYS at boot so the default dev experience needs no Postgres.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []*memEntry
}

// NewMemoryStore builds an in-process store from the bootstrap seed. Each seed's
// Identity is honored verbatim so a seeded key preserves its exact legacy tenant
// for backward compatibility.
func NewMemoryStore(seed []SeedKey) *MemoryStore {
	s := &MemoryStore{}
	for _, sk := range seed {
		if strings.TrimSpace(sk.Secret) == "" {
			continue
		}
		s.entries = append(s.entries, &memEntry{
			digest:   sha256.Sum256([]byte(sk.Secret)),
			key:      sk.Key,
			identity: sk.Identity,
		})
	}
	return s
}

func (s *MemoryStore) List(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.key)
	}
	// Newest first, matching the console's expectation that a just-created key
	// appears at the top of the list.
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func (s *MemoryStore) Create(_ context.Context, label string, rateLimitRpm int, creditBudget int64) (Key, string, error) {
	secret, last4 := generateSecret()
	id := generateID()
	key := Key{
		ID: id, Label: strings.TrimSpace(label), Last4: last4,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Status: "active",
		RateLimitRpm: rateLimitRpm, CreditBudget: creditBudget,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, &memEntry{
		digest:   sha256.Sum256([]byte(secret)),
		key:      key,
		identity: identityFor(id),
	})
	return key, secret, nil
}

func (s *MemoryStore) UpdateLimits(_ context.Context, id string, rateLimitRpm int, creditBudget int64) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.key.ID == id {
			e.key.RateLimitRpm = rateLimitRpm
			e.key.CreditBudget = creditBudget
			return e.key, nil
		}
	}
	return Key{}, ErrNotFound
}

func (s *MemoryStore) Revoke(_ context.Context, id string) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.key.ID == id {
			e.key.Status = "revoked"
			return e.key, nil
		}
	}
	return Key{}, ErrNotFound
}

// Authenticate compares the credential against every active entry in constant
// time, reusing auth.StaticAPIKeyAuthenticator's exact hashing/comparison
// approach (SHA-256 + subtle.ConstantTimeCompare over all entries) so timing
// cannot reveal which key prefix matched. A revoked key fails immediately.
func (s *MemoryStore) Authenticate(_ context.Context, credential string) (core.Identity, error) {
	credential = strings.TrimSpace(strings.TrimPrefix(credential, "Bearer "))
	if credential == "" {
		return core.Identity{}, auth.ErrUnauthorized
	}
	candidate := sha256.Sum256([]byte(credential))
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched core.Identity
	found := 0
	for _, e := range s.entries {
		if e.key.Status != "active" {
			continue
		}
		if subtle.ConstantTimeCompare(candidate[:], e.digest[:]) == 1 {
			matched = e.identity
			found = 1
		}
	}
	if found == 0 {
		return core.Identity{}, auth.ErrUnauthorized
	}
	return matched, nil
}
