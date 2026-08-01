package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jscyril/echelon/internal/core"
	"github.com/redis/go-redis/v9"
)

func newTestBucket(t *testing.T) (*RedisTokenBucket, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisTokenBucket(client), mr
}

func TestRedisTokenBucketExhaustsAndRefills(t *testing.T) {
	b, _ := newTestBucket(t)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }
	req := core.RateLimit{Key: "tenant-1", Cost: 1, Limit: 60, Burst: 3, Every: time.Minute}

	for i := 0; i < 3; i++ {
		d, err := b.Allow(context.Background(), req)
		if err != nil || !d.Allowed {
			t.Fatalf("call %d: allowed=%v err=%v", i, d.Allowed, err)
		}
	}
	if d, _ := b.Allow(context.Background(), req); d.Allowed {
		t.Fatalf("4th call should be denied")
	}
	// Refill at 60/min = 1/s; after 1s one token returns.
	now = now.Add(time.Second)
	if d, _ := b.Allow(context.Background(), req); !d.Allowed {
		t.Fatalf("expected allowance after refill")
	}
}

func TestRedisSeparateKeysAreIndependent(t *testing.T) {
	b, _ := newTestBucket(t)
	req := func(k string) core.RateLimit {
		return core.RateLimit{Key: k, Cost: 1, Limit: 1, Burst: 1, Every: time.Hour}
	}
	if d, _ := b.Allow(context.Background(), req("a")); !d.Allowed {
		t.Fatalf("key a first call should pass")
	}
	if d, _ := b.Allow(context.Background(), req("b")); !d.Allowed {
		t.Fatalf("key b must be independent of key a")
	}
	if d, _ := b.Allow(context.Background(), req("a")); d.Allowed {
		t.Fatalf("key a second call should be denied")
	}
}

func TestRedisInvalidConfigRejected(t *testing.T) {
	b, _ := newTestBucket(t)
	if _, err := b.Allow(context.Background(), core.RateLimit{Key: "k", Limit: 0, Burst: 1, Every: time.Second}); err == nil {
		t.Fatalf("expected error for non-positive limit")
	}
	if _, err := b.Allow(context.Background(), core.RateLimit{Key: "", Limit: 1, Burst: 1, Every: time.Second}); err == nil {
		t.Fatalf("expected error for empty key")
	}
}

// TestRedisConcurrentAllowNeverOverAdmits is the atomicity guarantee the in-memory
// package's doc comment defers to the Redis implementation: N goroutines hammer the
// same key with a small burst and no refill (frozen clock), and exactly `burst`
// admissions must succeed.
func TestRedisConcurrentAllowNeverOverAdmits(t *testing.T) {
	b, _ := newTestBucket(t)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now } // frozen: no refill during the race
	const burst = 10
	const goroutines = 200
	req := core.RateLimit{Key: "hot", Cost: 1, Limit: 1, Burst: burst, Every: time.Hour}

	var admitted int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := b.Allow(context.Background(), req)
			if err != nil {
				t.Errorf("allow: %v", err)
				return
			}
			if d.Allowed {
				atomic.AddInt64(&admitted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if admitted != burst {
		t.Fatalf("admitted=%d, want exactly burst=%d (atomicity violated)", admitted, burst)
	}
}
