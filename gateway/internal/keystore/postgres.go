package keystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/core"
)

// PostgresStore is a durable, pgxpool-backed API-key store modeled on
// telemetry.PostgresSink. The schema is created idempotently on construction.
// The digest UNIQUE constraint doubles as the index Authenticate looks keys up
// through.
type PostgresStore struct {
	pool *pgxpool.Pool
}

const createAPIKeysTable = `
CREATE TABLE IF NOT EXISTS api_keys (
  id             text PRIMARY KEY,
  label          text NOT NULL,
  digest         text NOT NULL UNIQUE,
  last4          text NOT NULL,
  created_at     timestamptz NOT NULL,
  status         text NOT NULL DEFAULT 'active',
  rate_limit_rpm int NOT NULL DEFAULT 1000,
  credit_budget  bigint NOT NULL DEFAULT 100000
);
`

// NewPostgresStore opens a pool from url, verifies connectivity, ensures the
// schema exists, and idempotently seeds the bootstrap keys. The caller owns
// Close.
func NewPostgresStore(ctx context.Context, url string, seed []SeedKey) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PostgresStore{pool: pool}
	if _, err := pool.Exec(ctx, createAPIKeysTable); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create api_keys schema: %w", err)
	}
	if err := s.seed(ctx, seed); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// seed inserts each bootstrap key with ON CONFLICT (id) DO NOTHING, mirroring
// RedisLedger's SETNX seeding: idempotent across restarts, so a second boot
// never resets anything the console has since changed.
func (s *PostgresStore) seed(ctx context.Context, seed []SeedKey) error {
	const q = `
INSERT INTO api_keys (id, label, digest, last4, created_at, status, rate_limit_rpm, credit_budget)
VALUES ($1, $2, $3, $4, $5::timestamptz, $6, $7, $8)
ON CONFLICT (id) DO NOTHING`
	for _, sk := range seed {
		if strings.TrimSpace(sk.Secret) == "" || sk.Key.ID == "" {
			continue
		}
		if _, err := s.pool.Exec(ctx, q,
			sk.Key.ID, sk.Key.Label, digestHex(sk.Secret), sk.Key.Last4,
			sk.Key.CreatedAt, sk.Key.Status, sk.Key.RateLimitRpm, sk.Key.CreditBudget,
		); err != nil {
			return fmt.Errorf("seed api key %q: %w", sk.Key.ID, err)
		}
	}
	return nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Key, error) {
	const q = `
SELECT id, label, last4, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
	status, rate_limit_rpm, credit_budget
FROM api_keys
ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query api_keys: %w", err)
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.Label, &k.Last4, &k.CreatedAt, &k.Status, &k.RateLimitRpm, &k.CreditBudget); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Create(ctx context.Context, label string, rateLimitRpm int, creditBudget int64) (Key, string, error) {
	secret, last4 := generateSecret()
	key := Key{
		ID: generateID(), Label: strings.TrimSpace(label), Last4: last4,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Status: "active",
		RateLimitRpm: rateLimitRpm, CreditBudget: creditBudget,
	}
	const q = `
INSERT INTO api_keys (id, label, digest, last4, created_at, status, rate_limit_rpm, credit_budget)
VALUES ($1, $2, $3, $4, $5::timestamptz, $6, $7, $8)`
	if _, err := s.pool.Exec(ctx, q,
		key.ID, key.Label, digestHex(secret), key.Last4, key.CreatedAt, key.Status, key.RateLimitRpm, key.CreditBudget,
	); err != nil {
		return Key{}, "", fmt.Errorf("insert api_key: %w", err)
	}
	return key, secret, nil
}

func (s *PostgresStore) UpdateLimits(ctx context.Context, id string, rateLimitRpm int, creditBudget int64) (Key, error) {
	const q = `
UPDATE api_keys SET rate_limit_rpm = $2, credit_budget = $3 WHERE id = $1
RETURNING id, label, last4, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), status, rate_limit_rpm, credit_budget`
	return s.scanOne(ctx, q, id, rateLimitRpm, creditBudget)
}

func (s *PostgresStore) Revoke(ctx context.Context, id string) (Key, error) {
	// Soft delete: flip status, keep the row, so historical telemetry keyed on
	// this id stays meaningful.
	const q = `
UPDATE api_keys SET status = 'revoked' WHERE id = $1
RETURNING id, label, last4, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), status, rate_limit_rpm, credit_budget`
	return s.scanOne(ctx, q, id)
}

func (s *PostgresStore) scanOne(ctx context.Context, q string, args ...any) (Key, error) {
	var k Key
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&k.ID, &k.Label, &k.Last4, &k.CreatedAt, &k.Status, &k.RateLimitRpm, &k.CreditBudget,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, fmt.Errorf("update api_key: %w", err)
	}
	return k, nil
}

// Authenticate resolves an active key by a single indexed-equality lookup on the
// digest. This deliberately diverges from MemoryStore's constant-time scan over
// every entry: a query planner leaking the number-of-entries-scanned signal is a
// far smaller concern than structured brute-force timing side-channels (which
// the SHA-256 digest — a fixed-width, uniformly-distributed value — defeats
// regardless of index), and this matches how essentially every production
// API-key system authenticates: an indexed hash lookup.
func (s *PostgresStore) Authenticate(ctx context.Context, credential string) (core.Identity, error) {
	credential = strings.TrimSpace(strings.TrimPrefix(credential, "Bearer "))
	if credential == "" {
		return core.Identity{}, auth.ErrUnauthorized
	}
	const q = `SELECT id FROM api_keys WHERE digest = $1 AND status = 'active'`
	var id string
	err := s.pool.QueryRow(ctx, q, digestHex(credential)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Identity{}, auth.ErrUnauthorized
	}
	if err != nil {
		return core.Identity{}, fmt.Errorf("authenticate lookup: %w", err)
	}
	return identityFor(id), nil
}

// Close releases the underlying connection pool.
func (s *PostgresStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
