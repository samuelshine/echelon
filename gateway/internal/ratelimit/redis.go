package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/redis/go-redis/v9"
)

// RedisTokenBucket is a distributed per-key token bucket backed by Redis. It
// satisfies ports.RateLimiter with the same token-bucket semantics as
// MemoryTokenBucket (capacity = req.Burst, refill = req.Limit / req.Every), but
// the read-modify-write is executed inside a single Lua script (EVAL) so that
// multiple gateway processes sharing one Redis instance cannot over-admit — this
// is the atomic distributed enforcement the package doc comment defers to the
// Redis implementation.
type RedisTokenBucket struct {
	client *redis.Client
	script *redis.Script
	now    func() time.Time
}

// allowScript refills the bucket, then admits one request of `cost` units iff
// enough tokens remain, storing the new bucket state with a TTL so idle keys are
// reclaimed. Returning the token count as a string preserves the fractional part
// (Redis truncates Lua numbers to integers on the wire).
//
//	KEYS[1] = bucket key
//	ARGV[1] = capacity (burst)      ARGV[2] = refill rate (tokens/sec)
//	ARGV[3] = now (unix seconds)    ARGV[4] = cost
//	ARGV[5] = ttl (milliseconds)
//	returns {allowed (0|1), tokens (string)}
const allowScript = `
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local tokens = tonumber(data[1])
local last = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  last = now
end
local delta = now - last
if delta < 0 then delta = 0 end
tokens = math.min(capacity, tokens + delta * rate)

local allowed = 0
if tokens >= cost then
  allowed = 1
  tokens = tokens - cost
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'last', tostring(now))
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, tostring(tokens)}
`

// NewRedisTokenBucket builds a Redis-backed limiter over the supplied client. The
// caller owns the client lifecycle (it is typically shared with the credit ledger).
func NewRedisTokenBucket(client *redis.Client) *RedisTokenBucket {
	return &RedisTokenBucket{
		client: client,
		script: redis.NewScript(allowScript),
		now:    time.Now,
	}
}

// Allow admits a request of req.Cost units against the bucket keyed by req.Key.
func (r *RedisTokenBucket) Allow(ctx context.Context, req core.RateLimit) (core.RateLimitDecision, error) {
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
	now := r.now()
	// TTL comfortably longer than one window so idle keys don't leak, but bounded
	// so state for abandoned keys is eventually reclaimed.
	ttlMs := (req.Every * 2).Milliseconds()

	res, err := r.script.Run(ctx, r.client, []string{req.Key},
		capacity,
		rate,
		float64(now.UnixNano())/1e9,
		cost,
		ttlMs,
	).Result()
	if err != nil {
		return core.RateLimitDecision{}, fmt.Errorf("redis rate limit: %w", err)
	}

	vals, ok := res.([]interface{})
	if !ok || len(vals) != 2 {
		return core.RateLimitDecision{}, fmt.Errorf("redis rate limit: unexpected reply %v", res)
	}
	allowed, _ := vals[0].(int64)
	tokensStr, _ := vals[1].(string)
	tokens, _ := strconv.ParseFloat(tokensStr, 64)

	if allowed == 1 {
		return core.RateLimitDecision{
			Allowed:   true,
			Remaining: int64(tokens),
			ResetAt:   now.Add(secondsToDuration((capacity - tokens) / rate)),
		}, nil
	}
	needed := float64(cost) - tokens
	return core.RateLimitDecision{
		Allowed:   false,
		Remaining: int64(tokens),
		ResetAt:   now.Add(secondsToDuration(needed / rate)),
	}, nil
}
