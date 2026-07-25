package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

func TestTokenBucketExhaustsAndRefills(t *testing.T) {
	now := time.Unix(0, 0)
	m := NewMemoryTokenBucket()
	m.now = func() time.Time { return now }
	req := core.RateLimit{Key: "tenant-1", Cost: 1, Limit: 60, Burst: 3, Every: time.Minute}

	// Burst of 3 allowed, 4th denied.
	for i := 0; i < 3; i++ {
		d, err := m.Allow(context.Background(), req)
		if err != nil || !d.Allowed {
			t.Fatalf("call %d: allowed=%v err=%v", i, d.Allowed, err)
		}
	}
	d, _ := m.Allow(context.Background(), req)
	if d.Allowed {
		t.Fatalf("4th call should be denied")
	}
	// Refill at 60/min = 1/s; after 1s one token returns.
	now = now.Add(time.Second)
	if d, _ := m.Allow(context.Background(), req); !d.Allowed {
		t.Fatalf("expected allowance after refill")
	}
}

func TestSeparateKeysAreIndependent(t *testing.T) {
	m := NewMemoryTokenBucket()
	req := func(k string) core.RateLimit {
		return core.RateLimit{Key: k, Cost: 1, Limit: 1, Burst: 1, Every: time.Hour}
	}
	if d, _ := m.Allow(context.Background(), req("a")); !d.Allowed {
		t.Fatalf("key a first call should pass")
	}
	if d, _ := m.Allow(context.Background(), req("b")); !d.Allowed {
		t.Fatalf("key b must be independent of key a")
	}
	if d, _ := m.Allow(context.Background(), req("a")); d.Allowed {
		t.Fatalf("key a second call should be denied")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	m := NewMemoryTokenBucket()
	if _, err := m.Allow(context.Background(), core.RateLimit{Key: "k", Limit: 0, Burst: 1, Every: time.Second}); err == nil {
		t.Fatalf("expected error for non-positive limit")
	}
}
