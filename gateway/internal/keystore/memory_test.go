package keystore

import (
	"context"
	"errors"
	"testing"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/core"
)

func TestMemoryStoreSeededAuthPreservesTenant(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore([]SeedKey{{
		Secret: "sk-demo",
		Key:    Key{ID: "acme", Label: "acme", Last4: "demo", CreatedAt: "2024-01-01T00:00:00Z", Status: "active", RateLimitRpm: 1000, CreditBudget: 100000},
		// Legacy identity preserved verbatim (keyid/plan from ECHELON_API_KEYS).
		Identity: core.Identity{TenantID: "acme", APIKeyID: "key_live", Plan: "pro"},
	}})

	id, err := s.Authenticate(ctx, "Bearer sk-demo")
	if err != nil {
		t.Fatalf("seeded key should authenticate: %v", err)
	}
	if id.TenantID != "acme" || id.APIKeyID != "key_live" || id.Plan != "pro" {
		t.Fatalf("seeded identity not preserved: %+v", id)
	}
	if _, err := s.Authenticate(ctx, "Bearer wrong"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("wrong key: want ErrUnauthorized, got %v", err)
	}
}

func TestMemoryStoreCreateRevokeLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(nil)

	key, secret, err := s.Create(ctx, "svc", DefaultRateLimitRpm, DefaultCreditBudget)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Created key is its own tenant.
	id, err := s.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("created key should authenticate: %v", err)
	}
	if id.TenantID != key.ID || id.APIKeyID != key.ID {
		t.Fatalf("created key tenancy: got %+v, want tenant==apikey==%s", id, key.ID)
	}

	if _, err := s.Revoke(ctx, key.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("revoked key must fail auth: got %v", err)
	}

	if _, err := s.Revoke(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: want ErrNotFound, got %v", err)
	}
}
