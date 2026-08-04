package credit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/redis/go-redis/v9"
)

// DefaultReservationTTL bounds how long a reservation may sit un-committed and
// un-released before its credits are reclaimed back into the tenant's balance.
// A crashed request (one that reserved but never committed or released) would
// otherwise lock those credits out of the balance forever. Ten minutes is
// comfortably longer than the largest configured REQUEST_TIMEOUT in this repo
// (50s), so an in-flight request is never reclaimed out from under itself.
const DefaultReservationTTL = 10 * time.Minute

// RedisLedger is a distributed credit ledger with the same reservation semantics
// as MemoryLedger, backed by Redis. Reserve/Commit/Release each run as a single
// Lua script (EVAL) so concurrent gateway processes sharing one Redis instance
// cannot over-spend a tenant's balance.
//
// Keys (all under keyPrefix, default "echelon:credit:"):
//
//	bal:<tenant>          integer, currently-available credits
//	holds:<tenant>        ZSET member=reservationID score=expiryUnixMillis
//	res:<reservationID>   hash {tenant, reserved}
//	idem:<tenant>\x00<k>  reservationID (with TTL), for idempotent Reserve
//
// A reservation's lifetime is governed by the holds ZSET rather than a per-key
// TTL: every Reserve first sweeps expired members of that tenant's holds set and
// refunds them, so abandoned reservations are lazily reclaimed atomically.
type RedisLedger struct {
	client    *redis.Client
	prefix    string
	ttl       time.Duration
	now       func() time.Time
	reserveSh *redis.Script
	commitSh  *redis.Script
	releaseSh *redis.Script
}

// reserveScript: sweep expired holds (refunding them), then honor idempotency,
// then atomically check-and-decrement the balance.
//
//	KEYS[1]=balKey  KEYS[2]=holdsKey  KEYS[3]=idemKey
//	ARGV[1]=resPrefix  ARGV[2]=tenant  ARGV[3]=maximum
//	ARGV[4]=newID  ARGV[5]=nowMs  ARGV[6]=ttlMs
//	returns {id, tenant, reserved(string), status("ok"|"insufficient")}
const reserveScript = `
local balKey = KEYS[1]
local holdsKey = KEYS[2]
local idemKey = KEYS[3]
local resPrefix = ARGV[1]
local tenant = ARGV[2]
local maximum = tonumber(ARGV[3])
local newID = ARGV[4]
local now = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])

-- 1. Reclaim expired holds (crashed requests) back into the balance.
local expired = redis.call('ZRANGEBYSCORE', holdsKey, '-inf', now)
for _, id in ipairs(expired) do
  local rk = resPrefix .. id
  local amt = redis.call('HGET', rk, 'reserved')
  if amt then redis.call('INCRBY', balKey, tonumber(amt)) end
  redis.call('DEL', rk)
  redis.call('ZREM', holdsKey, id)
end

-- 2. Idempotency: same (tenant, key) returns the existing live reservation.
local existing = redis.call('GET', idemKey)
if existing then
  local rk = resPrefix .. existing
  local v = redis.call('HMGET', rk, 'tenant', 'reserved')
  if v[1] then return {existing, v[1], v[2], 'ok'} end
end

-- 3. Balance check + atomic decrement.
local bal = tonumber(redis.call('GET', balKey))
if bal == nil then bal = 0 end
if bal < maximum then return {'', tenant, tostring(bal), 'insufficient'} end
redis.call('DECRBY', balKey, maximum)
local rk = resPrefix .. newID
redis.call('HSET', rk, 'tenant', tenant, 'reserved', maximum)
redis.call('ZADD', holdsKey, now + ttl, newID)
redis.call('SET', idemKey, newID, 'PX', ttl)
return {newID, tenant, tostring(maximum), 'ok'}
`

// commitScript charges actual (clamped to reserved), refunds the remainder, and
// clears the reservation.
//
//	KEYS[1]=balKey  KEYS[2]=holdsKey  KEYS[3]=resKey
//	ARGV[1]=resID  ARGV[2]=actual
//	returns {status("ok"|"unknown")}
const commitScript = `
local balKey = KEYS[1]
local holdsKey = KEYS[2]
local resKey = KEYS[3]
local resID = ARGV[1]
local actual = tonumber(ARGV[2])
local reserved = tonumber(redis.call('HGET', resKey, 'reserved'))
if reserved == nil then return {'unknown'} end
if actual < 0 then actual = 0 end
if actual > reserved then actual = reserved end
local refund = reserved - actual
if refund > 0 then redis.call('INCRBY', balKey, refund) end
redis.call('DEL', resKey)
redis.call('ZREM', holdsKey, resID)
return {'ok'}
`

// releaseScript refunds the full reserved amount and clears the reservation.
//
//	KEYS[1]=balKey  KEYS[2]=holdsKey  KEYS[3]=resKey
//	ARGV[1]=resID
//	returns {status("ok"|"unknown")}
const releaseScript = `
local balKey = KEYS[1]
local holdsKey = KEYS[2]
local resKey = KEYS[3]
local resID = ARGV[1]
local reserved = tonumber(redis.call('HGET', resKey, 'reserved'))
if reserved == nil then return {'unknown'} end
redis.call('INCRBY', balKey, reserved)
redis.call('DEL', resKey)
redis.call('ZREM', holdsKey, resID)
return {'ok'}
`

// NewRedisLedger builds a Redis-backed ledger over the supplied client and seeds
// each tenant's balance idempotently (SET ... NX) so restarting the gateway never
// resets a tenant who has already drawn down their balance. Pass ttl <= 0 to use
// DefaultReservationTTL. The caller owns the client lifecycle.
func NewRedisLedger(client *redis.Client, seed map[string]int64, ttl time.Duration) (*RedisLedger, error) {
	if ttl <= 0 {
		ttl = DefaultReservationTTL
	}
	l := &RedisLedger{
		client:    client,
		prefix:    "echelon:credit:",
		ttl:       ttl,
		now:       time.Now,
		reserveSh: redis.NewScript(reserveScript),
		commitSh:  redis.NewScript(commitScript),
		releaseSh: redis.NewScript(releaseScript),
	}
	for tenant, amount := range seed {
		// SETNX: only seed a tenant whose balance has never been set, so a
		// drawn-down balance survives restarts.
		if err := client.SetNX(context.Background(), l.balKey(tenant), amount, 0).Err(); err != nil {
			return nil, fmt.Errorf("credit seed for %q: %w", tenant, err)
		}
	}
	return l, nil
}

// Seed sets tenantID's initial balance if (and only if) it has never been set
// before, so it never clobbers a balance that's already been drawn down. This is
// the runtime analogue of NewRedisLedger's boot-time seed loop, used when the
// console creates a brand-new key/tenant after startup.
func (l *RedisLedger) Seed(ctx context.Context, tenantID string, amount int64) error {
	return l.client.SetNX(ctx, l.balKey(tenantID), amount, 0).Err()
}

func (l *RedisLedger) balKey(tenant string) string   { return l.prefix + "bal:" + tenant }
func (l *RedisLedger) holdsKey(tenant string) string { return l.prefix + "holds:" + tenant }
func (l *RedisLedger) resPrefix() string             { return l.prefix + "res:" }

// Balance reports a tenant's currently-available credits (test/admin helper).
func (l *RedisLedger) Balance(ctx context.Context, tenantID string) (int64, error) {
	v, err := l.client.Get(ctx, l.balKey(tenantID)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

// Reserve holds up to maximum credits. Repeating the same (tenant, idempotencyKey)
// returns the existing reservation without double-charging.
func (l *RedisLedger) Reserve(ctx context.Context, tenantID, idempotencyKey string, maximum int64) (core.CreditReservation, error) {
	if tenantID == "" || idempotencyKey == "" {
		return core.CreditReservation{}, fmt.Errorf("tenant and idempotency key are required")
	}
	if maximum < 0 {
		return core.CreditReservation{}, fmt.Errorf("reservation maximum must be non-negative")
	}
	idemKey := l.prefix + "idem:" + tenantID + "\x00" + idempotencyKey
	nowMs := l.now().UnixMilli()
	res, err := l.reserveSh.Run(ctx, l.client,
		[]string{l.balKey(tenantID), l.holdsKey(tenantID), idemKey},
		l.resPrefix(), tenantID, maximum, newID(), nowMs, l.ttl.Milliseconds(),
	).Result()
	if err != nil {
		return core.CreditReservation{}, fmt.Errorf("redis reserve: %w", err)
	}
	vals, ok := res.([]interface{})
	if !ok || len(vals) != 4 {
		return core.CreditReservation{}, fmt.Errorf("redis reserve: unexpected reply %v", res)
	}
	id, _ := vals[0].(string)
	tenant, _ := vals[1].(string)
	reserved := parseInt(vals[2])
	status, _ := vals[3].(string)
	if status == "insufficient" {
		return core.CreditReservation{}, fmt.Errorf("insufficient credits: have %d, need %d", reserved, maximum)
	}
	return core.CreditReservation{ID: id, TenantID: tenant, Reserved: reserved}, nil
}

// Commit charges actual (clamped to reserved) and refunds the remainder.
func (l *RedisLedger) Commit(ctx context.Context, reservation core.CreditReservation, actual int64) error {
	if actual < 0 {
		return fmt.Errorf("actual usage must be non-negative")
	}
	res, err := l.commitSh.Run(ctx, l.client,
		[]string{l.balKey(reservation.TenantID), l.holdsKey(reservation.TenantID), l.resPrefix() + reservation.ID},
		reservation.ID, actual,
	).Result()
	if err != nil {
		return fmt.Errorf("redis commit: %w", err)
	}
	return unknownReservationErr(res, reservation.ID)
}

// Release returns the full reserved amount (e.g., blocked or failed request).
func (l *RedisLedger) Release(ctx context.Context, reservation core.CreditReservation) error {
	res, err := l.releaseSh.Run(ctx, l.client,
		[]string{l.balKey(reservation.TenantID), l.holdsKey(reservation.TenantID), l.resPrefix() + reservation.ID},
		reservation.ID,
	).Result()
	if err != nil {
		return fmt.Errorf("redis release: %w", err)
	}
	return unknownReservationErr(res, reservation.ID)
}

func unknownReservationErr(res any, id string) error {
	vals, ok := res.([]interface{})
	if ok && len(vals) == 1 {
		if status, _ := vals[0].(string); status == "unknown" {
			return fmt.Errorf("unknown reservation %q", id)
		}
	}
	return nil
}

// parseInt coerces a Lua reply element (int64 or numeric string) to int64.
func parseInt(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}
