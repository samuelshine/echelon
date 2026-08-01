package telemetry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresSink is a durable Sink backed by a pgxpool.Pool. It persists each
// PromptEvent to a single `prompt_events` table (created idempotently on
// construction) and can rehydrate the most recent rows on startup. It records
// only the privacy-safe fields already present on PromptEvent — no raw prompt or
// response text ever reaches this table (Excerpt is a hardcoded "[redacted]").
type PostgresSink struct {
	pool *pgxpool.Pool
}

const createPromptEventsTable = `
CREATE TABLE IF NOT EXISTS prompt_events (
	id                    text PRIMARY KEY,
	ts                    timestamptz NOT NULL,
	direction             text NOT NULL,
	final_verdict         text NOT NULL,
	risk_score            double precision NOT NULL DEFAULT 0,
	category              text NOT NULL DEFAULT '',
	blocked_at_layer      text NOT NULL DEFAULT '',
	layers                jsonb NOT NULL DEFAULT '[]'::jsonb,
	tokens_in             int NOT NULL DEFAULT 0,
	tokens_out            int NOT NULL DEFAULT 0,
	latency_overhead_us   bigint NOT NULL DEFAULT 0,
	api_key_id            text NOT NULL DEFAULT '',
	provider              text NOT NULL DEFAULT '',
	excerpt               text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS prompt_events_ts_idx ON prompt_events (ts DESC);
`

// NewPostgresSink opens a pgx connection pool from url, verifies connectivity,
// and ensures the schema exists. The caller owns Close.
func NewPostgresSink(ctx context.Context, url string) (*PostgresSink, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PostgresSink{pool: pool}
	if err := s.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *PostgresSink) ensureSchema(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, createPromptEventsTable); err != nil {
		return fmt.Errorf("create prompt_events schema: %w", err)
	}
	return nil
}

// Record durably inserts one event. ON CONFLICT DO NOTHING makes replays and
// hydrate/re-record races idempotent on the event id. The ts column is stored as
// a real timestamptz parsed from the RFC3339 string the Store stamps.
func (s *PostgresSink) Record(ctx context.Context, e PromptEvent) error {
	layers, err := json.Marshal(e.Layers)
	if err != nil {
		return fmt.Errorf("marshal layers: %w", err)
	}
	const q = `
INSERT INTO prompt_events (
	id, ts, direction, final_verdict, risk_score, category, blocked_at_layer,
	layers, tokens_in, tokens_out, latency_overhead_us, api_key_id, provider, excerpt
) VALUES ($1, $2::timestamptz, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO NOTHING`
	_, err = s.pool.Exec(ctx, q,
		e.ID, e.Ts, e.Direction, e.FinalVerdict, e.RiskScore, e.Category,
		e.BlockedAtLayer, string(layers), e.Tokens.In, e.Tokens.Out,
		e.LatencyOverheadUs, e.APIKeyID, e.Provider, e.Excerpt,
	)
	if err != nil {
		return fmt.Errorf("insert prompt_event: %w", err)
	}
	return nil
}

// Recent returns up to limit most-recent events in chronological (oldest-first)
// order, suitable to pass straight to Store.Hydrate.
func (s *PostgresSink) Recent(ctx context.Context, limit int) ([]PromptEvent, error) {
	if limit <= 0 {
		limit = 5000
	}
	const q = `
SELECT id, to_char(ts, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts, direction, final_verdict,
	risk_score, category, blocked_at_layer, layers, tokens_in, tokens_out,
	latency_overhead_us, api_key_id, provider, excerpt
FROM prompt_events
ORDER BY ts DESC
LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent prompt_events: %w", err)
	}
	defer rows.Close()

	var out []PromptEvent
	for rows.Next() {
		var e PromptEvent
		var layers []byte
		if err := rows.Scan(
			&e.ID, &e.Ts, &e.Direction, &e.FinalVerdict, &e.RiskScore, &e.Category,
			&e.BlockedAtLayer, &layers, &e.Tokens.In, &e.Tokens.Out,
			&e.LatencyOverheadUs, &e.APIKeyID, &e.Provider, &e.Excerpt,
		); err != nil {
			return nil, fmt.Errorf("scan prompt_event: %w", err)
		}
		if len(layers) > 0 {
			_ = json.Unmarshal(layers, &e.Layers)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse into chronological (oldest-first) order for the ring buffer.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// Close releases the underlying connection pool.
func (s *PostgresSink) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
