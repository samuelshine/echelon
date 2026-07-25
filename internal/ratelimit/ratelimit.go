// Package ratelimit provides in-memory admission control for single-process
// development. A Redis/Lua token bucket for distributed enforcement is introduced
// later; both satisfy ports.RateLimiter so the application core is unchanged.
package ratelimit

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

// MemoryTokenBucket is a thread-safe per-key token bucket. Capacity is the burst
// size; tokens refill at Limit per Every. It is safe for concurrent use.
type MemoryTokenBucket struct {
	mu    sync.Mutex
	state map[string]*bucket
	now   func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewMemoryTokenBucket() *MemoryTokenBucket {
	return &MemoryTokenBucket{state: make(map[string]*bucket), now: time.Now}
}

// Allow admits a request of req.Cost units against the bucket keyed by req.Key.
func (m *MemoryTokenBucket) Allow(_ context.Context, req core.RateLimit) (core.RateLimitDecision, error) {
	if req.Key == "" {
		return core.RateLimitDecision{}, fmt.Errorf("rate limit key is required")
	}
	if req.Limit <= 0 || req.Every <= 0 || req.Burst <= 0 {
		return core.RateLimitDecision{}, fmt.Errorf("rate limit requires positive limit, burst, and window")
	}
	cost := req.Cost
	if cost <= 0 {
		cost = 1
	}
	capacity := float64(req.Burst)
	rate := float64(req.Limit) / req.Every.Seconds() // tokens per second

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	b := m.state[req.Key]
	if b == nil {
		b = &bucket{tokens: capacity, last: now}
		m.state[req.Key] = b
	}
	b.tokens = math.Min(capacity, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now

	if b.tokens >= float64(cost) {
		b.tokens -= float64(cost)
		return core.RateLimitDecision{
			Allowed:   true,
			Remaining: int64(b.tokens),
			ResetAt:   now.Add(secondsToDuration((capacity - b.tokens) / rate)),
		}, nil
	}
	needed := float64(cost) - b.tokens
	return core.RateLimitDecision{
		Allowed:   false,
		Remaining: int64(b.tokens),
		ResetAt:   now.Add(secondsToDuration(needed / rate)),
	}, nil
}

func secondsToDuration(seconds float64) time.Duration {
	if seconds < 0 || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}
