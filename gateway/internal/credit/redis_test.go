package credit

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestLedger(t *testing.T, seed map[string]int64) *RedisLedger {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	l, err := NewRedisLedger(client, seed, 0)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	return l
}

func bal(t *testing.T, l *RedisLedger, tenant string) int64 {
	t.Helper()
	v, err := l.Balance(context.Background(), tenant)
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	return v
}

func TestRedisReserveCommitRefundsUnused(t *testing.T) {
	l := newTestLedger(t, map[string]int64{"acme": 100})
	res, err := l.Reserve(context.Background(), "acme", "req-1", 40)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if bal(t, l, "acme") != 60 {
		t.Fatalf("balance after reserve = %d, want 60", bal(t, l, "acme"))
	}
	if err := l.Commit(context.Background(), res, 25); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if bal(t, l, "acme") != 75 { // 60 + (40-25) refund
		t.Fatalf("balance after commit = %d, want 75", bal(t, l, "acme"))
	}
}

func TestRedisReleaseReturnsFullReservation(t *testing.T) {
	l := newTestLedger(t, map[string]int64{"acme": 50})
	res, _ := l.Reserve(context.Background(), "acme", "req-2", 30)
	if err := l.Release(context.Background(), res); err != nil {
		t.Fatalf("release: %v", err)
	}
	if bal(t, l, "acme") != 50 {
		t.Fatalf("balance after release = %d, want 50", bal(t, l, "acme"))
	}
}

func TestRedisReserveIsIdempotent(t *testing.T) {
	l := newTestLedger(t, map[string]int64{"acme": 100})
	a, _ := l.Reserve(context.Background(), "acme", "same-key", 40)
	b, err := l.Reserve(context.Background(), "acme", "same-key", 40)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if a.ID != b.ID {
		t.Fatalf("idempotent reserve returned different IDs")
	}
	if bal(t, l, "acme") != 60 { // charged once
		t.Fatalf("balance = %d, want 60 (charged once)", bal(t, l, "acme"))
	}
}

func TestRedisReserveInsufficientBalance(t *testing.T) {
	l := newTestLedger(t, map[string]int64{"acme": 10})
	if _, err := l.Reserve(context.Background(), "acme", "req", 40); err == nil {
		t.Fatalf("expected insufficient-credit error")
	}
}

func TestRedisSeedIsIdempotentAcrossRestart(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	l1, err := NewRedisLedger(client, map[string]int64{"acme": 100}, 0)
	if err != nil {
		t.Fatalf("ledger 1: %v", err)
	}
	if _, err := l1.Reserve(context.Background(), "acme", "spend", 40); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Simulate a restart: rebuild the ledger with the same seed. SETNX must not
	// reset the drawn-down balance.
	l2, err := NewRedisLedger(client, map[string]int64{"acme": 100}, 0)
	if err != nil {
		t.Fatalf("ledger 2: %v", err)
	}
	if got := bal(t, l2, "acme"); got != 60 {
		t.Fatalf("balance after restart = %d, want 60 (seed must not reset a drawn-down tenant)", got)
	}
}

// TestRedisConcurrentReserveNeverOverspends: N goroutines race Reserve against a
// balance that can satisfy only a few, and the total reserved must never exceed
// the starting balance.
func TestRedisConcurrentReserveNeverOverspends(t *testing.T) {
	const start = 30
	const perReq = 1
	const goroutines = 200
	l := newTestLedger(t, map[string]int64{"acme": start})

	var success int64
	var wg sync.WaitGroup
	begin := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-begin
			// Distinct idempotency keys so each is a genuine competing reservation.
			if _, err := l.Reserve(context.Background(), "acme", key(n), perReq); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}
	close(begin)
	wg.Wait()

	if success*perReq > start {
		t.Fatalf("overspend: %d successful reservations * %d > starting balance %d", success, perReq, start)
	}
	if success != start/perReq {
		t.Fatalf("successful reservations = %d, want %d (exact fill of balance)", success, start/perReq)
	}
	if got := bal(t, l, "acme"); got != start-success*perReq {
		t.Fatalf("residual balance = %d, want %d", got, start-success*perReq)
	}
}

func key(n int) string {
	return "req-" + strconv.Itoa(n)
}
