package credit

import (
	"context"
	"testing"
)

func TestReserveCommitRefundsUnused(t *testing.T) {
	l := NewMemoryLedger(map[string]int64{"acme": 100})
	res, err := l.Reserve(context.Background(), "acme", "req-1", 40)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if l.Balance("acme") != 60 {
		t.Fatalf("balance after reserve = %d, want 60", l.Balance("acme"))
	}
	if err := l.Commit(context.Background(), res, 25); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if l.Balance("acme") != 75 { // 60 + (40-25) refund
		t.Fatalf("balance after commit = %d, want 75", l.Balance("acme"))
	}
}

func TestReleaseReturnsFullReservation(t *testing.T) {
	l := NewMemoryLedger(map[string]int64{"acme": 50})
	res, _ := l.Reserve(context.Background(), "acme", "req-2", 30)
	if err := l.Release(context.Background(), res); err != nil {
		t.Fatalf("release: %v", err)
	}
	if l.Balance("acme") != 50 {
		t.Fatalf("balance after release = %d, want 50", l.Balance("acme"))
	}
}

func TestReserveIsIdempotent(t *testing.T) {
	l := NewMemoryLedger(map[string]int64{"acme": 100})
	a, _ := l.Reserve(context.Background(), "acme", "same-key", 40)
	b, err := l.Reserve(context.Background(), "acme", "same-key", 40)
	if err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	if a.ID != b.ID {
		t.Fatalf("idempotent reserve returned different IDs")
	}
	if l.Balance("acme") != 60 { // charged once
		t.Fatalf("balance = %d, want 60 (charged once)", l.Balance("acme"))
	}
}

func TestReserveInsufficientBalance(t *testing.T) {
	l := NewMemoryLedger(map[string]int64{"acme": 10})
	if _, err := l.Reserve(context.Background(), "acme", "req", 40); err == nil {
		t.Fatalf("expected insufficient-credit error")
	}
}
