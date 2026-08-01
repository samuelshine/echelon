package telemetry

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPostgresSinkRoundTrip exercises the real DDL/insert/hydrate path, but only
// when a Postgres is reachable. Docker is not available in CI here, so absent a
// live DB (via AUDIT_TEST_DATABASE_URL) the test skips cleanly rather than
// failing or hanging.
func TestPostgresSinkRoundTrip(t *testing.T) {
	url := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUDIT_TEST_DATABASE_URL not set; skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sink, err := NewPostgresSink(ctx, url)
	if err != nil {
		t.Skipf("Postgres not reachable (%v); skipping", err)
	}
	defer sink.Close()

	ev := PromptEvent{
		ID: "evt_test_1", Ts: "2026-08-01T12:00:00Z", Direction: "ingress",
		FinalVerdict: "block", RiskScore: 0.91, Category: "jailbreak",
		BlockedAtLayer: "llm_judge",
		Layers: []LayerResult{
			{Layer: "heuristics", Verdict: "pass", Score: 0.1},
			{Layer: "llm_judge", Verdict: "block", Score: 0.91},
		},
		Tokens: Tokens{In: 10, Out: 20}, LatencyOverheadUs: 1234,
		APIKeyID: "key_live", Provider: "openai", Excerpt: "[redacted]",
	}
	if err := sink.Record(ctx, ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Idempotent replay must not error.
	if err := sink.Record(ctx, ev); err != nil {
		t.Fatalf("Record (replay): %v", err)
	}

	recent, err := sink.Recent(ctx, 100)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	var found *PromptEvent
	for i := range recent {
		if recent[i].ID == "evt_test_1" {
			found = &recent[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("inserted event not returned by Recent")
	}
	if found.FinalVerdict != "block" || found.Category != "jailbreak" || len(found.Layers) != 2 {
		t.Fatalf("round-tripped event mismatch: %+v", *found)
	}
}
