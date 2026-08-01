package telemetry

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// blockingSink blocks forever inside Record, simulating a stalled/unavailable DB.
type blockingSink struct{ entered chan struct{} }

func (b *blockingSink) Record(ctx context.Context, e PromptEvent) error {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done() // never proceed on our own; only unblock via ctx cancel
	return ctx.Err()
}

// recordingSink captures events for ordering/assertion.
type recordingSink struct {
	mu     sync.Mutex
	events []PromptEvent
}

func (r *recordingSink) Record(ctx context.Context, e PromptEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingSink) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Record must never block or panic even when the sink is wedged and the buffer
// is saturated — durability is best-effort and must not touch the hot path.
func TestRecordNeverBlocksUnderBackpressure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewStore(100)
	sink := &blockingSink{entered: make(chan struct{}, 1)}
	s.runSinkWithBuffer(ctx, sink, discardLogger(), 1)

	// Prime the drain goroutine so it is stuck inside Record on the first event.
	s.Record(PromptEvent{ID: "e0"})
	select {
	case <-sink.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain goroutine never entered blocking sink")
	}

	// Now the goroutine is blocked and the 1-slot buffer will saturate. Every
	// subsequent Record must still return promptly (dropping under the default
	// select case), not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10_000; i++ {
			s.Record(PromptEvent{ID: "flood"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Record blocked under backpressure")
	}

	// In-memory ring must still have received every event synchronously.
	if got := len(s.Events(0)); got != 100 { // capped at capacity
		t.Fatalf("ring size = %d, want 100 (capacity)", got)
	}
	s.mu.Lock()
	dropped := s.dropped
	s.mu.Unlock()
	if dropped == 0 {
		t.Fatal("expected some dropped events under backpressure, got 0")
	}
}

// A configured sink must durably receive events handed off from Record.
func TestRecordForwardsToSink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewStore(100)
	sink := &recordingSink{}
	s.runSinkWithBuffer(ctx, sink, discardLogger(), 64)

	for i := 0; i < 20; i++ {
		s.Record(PromptEvent{ID: "e", FinalVerdict: "pass"})
	}

	deadline := time.After(2 * time.Second)
	for sink.len() < 20 {
		select {
		case <-deadline:
			t.Fatalf("sink received %d/20 events", sink.len())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Hydrate restores chronological (oldest-first) order and respects capacity, so
// Events() (newest-first) reflects the most recent rows after a restart.
func TestHydrateOrderingAndCapacity(t *testing.T) {
	s := NewStore(3)
	// Oldest-first input, more than capacity.
	s.Hydrate([]PromptEvent{
		{ID: "a", Ts: "2026-08-01T00:00:01Z"},
		{ID: "b", Ts: "2026-08-01T00:00:02Z"},
		{ID: "c", Ts: "2026-08-01T00:00:03Z"},
		{ID: "d", Ts: "2026-08-01T00:00:04Z"},
	})
	got := s.Events(0) // newest-first
	if len(got) != 3 {
		t.Fatalf("hydrated ring size = %d, want 3", len(got))
	}
	wantOrder := []string{"d", "c", "b"}
	for i, w := range wantOrder {
		if got[i].ID != w {
			t.Fatalf("Events()[%d].ID = %q, want %q", i, got[i].ID, w)
		}
	}
}

// With no sink configured, Record stays purely in-memory and never blocks.
func TestRecordWithoutSink(t *testing.T) {
	s := NewStore(10)
	s.Record(PromptEvent{ID: "x"})
	if len(s.Events(0)) != 1 {
		t.Fatalf("expected 1 event, got %d", len(s.Events(0)))
	}
}
