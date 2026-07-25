// Package credit provides an in-memory credit ledger with reservation semantics
// so rejected or failed upstream calls never permanently consume a tenant's
// balance. It satisfies ports.CreditLedger.
package credit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/jscyril/echelon/internal/core"
)

type MemoryLedger struct {
	mu           sync.Mutex
	balances     map[string]int64
	reservations map[string]core.CreditReservation
	idempotency  map[string]string // tenant\x00key -> reservation ID
}

func NewMemoryLedger(initial map[string]int64) *MemoryLedger {
	balances := make(map[string]int64, len(initial))
	for tenant, amount := range initial {
		balances[tenant] = amount
	}
	return &MemoryLedger{
		balances:     balances,
		reservations: make(map[string]core.CreditReservation),
		idempotency:  make(map[string]string),
	}
}

// Credit tops up a tenant balance (test/admin helper).
func (l *MemoryLedger) Credit(tenantID string, amount int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.balances[tenantID] += amount
}

func (l *MemoryLedger) Balance(tenantID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balances[tenantID]
}

// Reserve holds up to maximum credits. Repeating the same (tenant, idempotencyKey)
// returns the existing reservation without double-charging.
func (l *MemoryLedger) Reserve(_ context.Context, tenantID, idempotencyKey string, maximum int64) (core.CreditReservation, error) {
	if tenantID == "" || idempotencyKey == "" {
		return core.CreditReservation{}, fmt.Errorf("tenant and idempotency key are required")
	}
	if maximum < 0 {
		return core.CreditReservation{}, fmt.Errorf("reservation maximum must be non-negative")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	idKey := tenantID + "\x00" + idempotencyKey
	if existingID, ok := l.idempotency[idKey]; ok {
		return l.reservations[existingID], nil
	}
	if l.balances[tenantID] < maximum {
		return core.CreditReservation{}, fmt.Errorf("insufficient credits: have %d, need %d", l.balances[tenantID], maximum)
	}
	l.balances[tenantID] -= maximum
	reservation := core.CreditReservation{ID: newID(), TenantID: tenantID, Reserved: maximum}
	l.reservations[reservation.ID] = reservation
	l.idempotency[idKey] = reservation.ID
	return reservation, nil
}

// Commit charges actual (clamped to reserved) and refunds the remainder.
func (l *MemoryLedger) Commit(_ context.Context, reservation core.CreditReservation, actual int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	held, ok := l.reservations[reservation.ID]
	if !ok {
		return fmt.Errorf("unknown reservation %q", reservation.ID)
	}
	if actual < 0 {
		return fmt.Errorf("actual usage must be non-negative")
	}
	if actual > held.Reserved {
		actual = held.Reserved
	}
	l.balances[held.TenantID] += held.Reserved - actual
	delete(l.reservations, reservation.ID)
	return nil
}

// Release returns the full reserved amount (e.g., blocked or failed request).
func (l *MemoryLedger) Release(_ context.Context, reservation core.CreditReservation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	held, ok := l.reservations[reservation.ID]
	if !ok {
		return fmt.Errorf("unknown reservation %q", reservation.ID)
	}
	l.balances[held.TenantID] += held.Reserved
	delete(l.reservations, reservation.ID)
	return nil
}

func newID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
