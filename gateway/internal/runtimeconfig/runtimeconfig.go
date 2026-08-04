// Package runtimeconfig persists the operator's live threshold/toggle overrides
// so a change made from the console survives a gateway restart. It is a single
// JSON row in Postgres, sharing the same connection/URL (AUDIT_DATABASE_URL) as
// the audit sink and key store. When Postgres is not configured there is no
// persistence — overrides still apply live in-process but are lost on restart.
package runtimeconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Overrides holds the operator-set values that diverge from the env-configured
// defaults. Every field is a pointer so "unset" (nil) is distinguishable from
// "explicitly set to the zero value".
type Overrides struct {
	JudgeThreshold    *float64 `json:"judgeThreshold,omitempty"`
	BlockThreshold    *float64 `json:"blockThreshold,omitempty"`
	PIIMasking        *bool    `json:"piiMasking,omitempty"`
	PolicyEnforcement *bool    `json:"policyEnforcement,omitempty"`
	// ToxicityScan also drives maliciousCodeScan: the two verdicts come from one
	// classifier call (the response_classifier scanner), so they cannot be
	// toggled independently.
	ToxicityScan *bool `json:"toxicityScan,omitempty"`
}

// Store is a single-row Postgres-backed override store, modeled on
// telemetry.PostgresSink.
type Store struct {
	pool *pgxpool.Pool
}

const createRuntimeConfigTable = `
CREATE TABLE IF NOT EXISTS runtime_config (
  id    int PRIMARY KEY DEFAULT 1,
  data  jsonb NOT NULL,
  CHECK (id = 1)
);
`

// NewStore opens a pool from url, verifies connectivity, and ensures the schema.
// The caller owns Close.
func NewStore(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, createRuntimeConfigTable); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create runtime_config schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Load returns the persisted overrides. The bool reports whether a row exists
// (false on a fresh database — the caller then simply applies no overrides).
func (s *Store) Load(ctx context.Context) (Overrides, bool, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT data FROM runtime_config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Overrides{}, false, nil
	}
	if err != nil {
		return Overrides{}, false, fmt.Errorf("load runtime_config: %w", err)
	}
	var ov Overrides
	if err := json.Unmarshal(raw, &ov); err != nil {
		return Overrides{}, false, fmt.Errorf("unmarshal runtime_config: %w", err)
	}
	return ov, true, nil
}

// Save upserts the single override row.
func (s *Store) Save(ctx context.Context, ov Overrides) error {
	data, err := json.Marshal(ov)
	if err != nil {
		return fmt.Errorf("marshal runtime_config: %w", err)
	}
	const q = `
INSERT INTO runtime_config (id, data) VALUES (1, $1::jsonb)
ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`
	if _, err := s.pool.Exec(ctx, q, string(data)); err != nil {
		return fmt.Errorf("save runtime_config: %w", err)
	}
	return nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
