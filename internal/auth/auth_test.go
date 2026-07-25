package auth

import (
	"context"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestAuthenticateKnownAndUnknownKeys(t *testing.T) {
	a, err := NewStaticAPIKeyAuthenticator(map[string]core.Identity{
		"sk-alpha": {TenantID: "acme", APIKeyID: "k1", Plan: "pro"},
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	id, err := a.Authenticate(context.Background(), "Bearer sk-alpha")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.TenantID != "acme" || id.APIKeyID != "k1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if _, err := a.Authenticate(context.Background(), "sk-wrong"); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
	if _, err := a.Authenticate(context.Background(), ""); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for empty, got %v", err)
	}
}
