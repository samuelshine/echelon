// Package telemetry keeps a bounded, privacy-safe in-memory record of gateway
// decisions and renders them in the exact shapes the Echelon console consumes.
// No raw prompt or response text is stored — only verdicts, scores, timing, and
// identifiers.
package telemetry

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// LayerResult mirrors the console's per-stage ruling (camelCase JSON).
type LayerResult struct {
	Layer     string         `json:"layer"`
	Verdict   string         `json:"verdict"`
	Score     float64        `json:"score"`
	Threshold float64        `json:"threshold"`
	Model     string         `json:"model,omitempty"`
	LatencyUs int64          `json:"latencyUs"`
	Detail    map[string]any `json:"detail"`
}

type Tokens struct {
	In  int `json:"in"`
	Out int `json:"out"`
}

// PromptEvent mirrors the console's log row.
type PromptEvent struct {
	ID                string        `json:"id"`
	Ts                string        `json:"ts"`
	Direction         string        `json:"direction"`
	FinalVerdict      string        `json:"finalVerdict"`
	RiskScore         float64       `json:"riskScore"`
	Category          string        `json:"category"`
	BlockedAtLayer    string        `json:"blockedAtLayer,omitempty"`
	Layers            []LayerResult `json:"layers"`
	Tokens            Tokens        `json:"tokens"`
	LatencyOverheadUs int64         `json:"latencyOverheadUs"`
	APIKeyID          string        `json:"apiKeyId"`
	Provider          string        `json:"provider,omitempty"`
	Excerpt           string        `json:"excerpt"`
	// Terminal marks whether this event represents the end of request handling
	// for its call (a block, or the final post-egress/passthrough outcome).
	// json:"-" so it never reaches the wire shape or the console's schema -- it
	// exists purely to stop Summary from double-counting a single API call that
	// now produces two events for an allowed request (an ingress-pass record
	// plus the final one; see recordEvent in internal/gateway).
	Terminal bool `json:"-"`
}

// Sink is an optional durable destination for events. It is deliberately local
// to the telemetry package (keyed on PromptEvent, the real recorded shape) rather
// than a generic audit port. Implementations must tolerate being called from a
// single background goroutine and should honor ctx cancellation.
type Sink interface {
	Record(ctx context.Context, e PromptEvent) error
}

// Store is a thread-safe ring buffer of events, with an optional best-effort
// durable Sink drained by a background goroutine.
type Store struct {
	mu       sync.RWMutex
	events   []PromptEvent
	capacity int
	seq      int64
	now      func() time.Time

	// Durable-sink plumbing (nil unless RunSink was called). sinkCh is a bounded
	// buffered channel; Record does a non-blocking send onto it so a slow or
	// unavailable Sink can never add latency to or fail a request.
	sinkCh   chan PromptEvent
	logger   *slog.Logger
	dropped  int64
	lastWarn time.Time

	// Live-tail broadcast plumbing. Each console SSE subscriber gets a small
	// buffered channel; Record does a best-effort non-blocking send to each under
	// the same mutex Subscribe's unsubscribe uses to delete+close, so a send can
	// never race a close (no send-on-closed-channel panic). A slow/absent
	// subscriber simply misses frames and never adds latency to Record.
	subscribers map[chan PromptEvent]struct{}
}

func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = 5000
	}
	return &Store{capacity: capacity, now: time.Now}
}

// Record appends an event to the in-memory ring (fully synchronous, unchanged
// behavior) and, when a durable Sink is configured, additionally performs a
// non-blocking hand-off to the background drain goroutine. The hand-off never
// blocks: if the buffer is full the event is dropped and a rate-limited warning
// is logged — durability is best-effort and must never stall the hot path.
func (s *Store) Record(e PromptEvent) {
	s.mu.Lock()
	if e.Ts == "" {
		e.Ts = s.now().UTC().Format(time.RFC3339)
	}
	s.events = append(s.events, e)
	if len(s.events) > s.capacity {
		s.events = s.events[len(s.events)-s.capacity:]
	}
	// Best-effort live-tail broadcast. Done under the lock (non-blocking sends, so
	// it never stalls) precisely so a concurrent unsubscribe — which deletes then
	// closes the channel under this same lock — can never race an in-flight send.
	for sub := range s.subscribers {
		select {
		case sub <- e:
		default:
		}
	}
	ch := s.sinkCh
	s.mu.Unlock()

	if ch == nil {
		return
	}
	select {
	case ch <- e:
	default:
		s.warnDrop()
	}
}

// warnDrop counts dropped events and logs at most once every 5s to avoid log
// floods under sustained backpressure.
func (s *Store) warnDrop() {
	s.mu.Lock()
	s.dropped++
	dropped := s.dropped
	now := s.now()
	shouldWarn := now.Sub(s.lastWarn) >= 5*time.Second
	if shouldWarn {
		s.lastWarn = now
	}
	logger := s.logger
	s.mu.Unlock()
	if shouldWarn && logger != nil {
		logger.Warn("telemetry durable sink buffer full; dropping events", "dropped_total", dropped)
	}
}

// RunSink wires a durable Sink and starts the single background drain goroutine.
// It is idempotent-safe to call once at startup; the goroutine stops when ctx is
// cancelled (hook it to main.go's signal.NotifyContext). A nil sink is a no-op,
// leaving the Store purely in-memory.
func (s *Store) RunSink(ctx context.Context, sink Sink, logger *slog.Logger) {
	s.runSinkWithBuffer(ctx, sink, logger, 1024)
}

// runSinkWithBuffer is the tunable core of RunSink; buffer sizing is exposed to
// tests so backpressure/drop behavior can be exercised deterministically.
func (s *Store) runSinkWithBuffer(ctx context.Context, sink Sink, logger *slog.Logger, buffer int) {
	if sink == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	if buffer <= 0 {
		buffer = 1
	}
	ch := make(chan PromptEvent, buffer)
	s.mu.Lock()
	if s.sinkCh != nil { // already running; do not start a second drainer
		s.mu.Unlock()
		return
	}
	s.sinkCh = ch
	s.logger = logger
	s.mu.Unlock()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-ch:
				writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := sink.Record(writeCtx, e); err != nil {
					logger.Warn("telemetry durable sink write failed", "error", err)
				}
				cancel()
			}
		}
	}()
}

// Hydrate replaces the in-memory ring with the supplied events (chronological,
// oldest-first), keeping at most capacity of them. Used at startup to restore the
// most recent rows from a durable Sink so a restart does not show an empty
// console.
func (s *Store) Hydrate(events []PromptEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(events) > s.capacity {
		events = events[len(events)-s.capacity:]
	}
	s.events = append(s.events[:0:0], events...)
}

// Capacity returns the ring buffer's configured capacity.
func (s *Store) Capacity() int {
	return s.capacity
}

// Events returns up to limit most-recent events, newest first.
func (s *Store) Events(limit int) []PromptEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]PromptEvent, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, s.events[i])
	}
	return out
}

// QueryOptions is the server-side filter + pagination request for the console's
// log surface. It ports console/lib/logs.ts's applyFilters faithfully: an empty
// (or "all") string dimension means "no filter". Iteration is newest-first,
// mirroring Events.
type QueryOptions struct {
	Verdict   string  // "", "all", "pass", "flag", "block" — exact match on FinalVerdict
	Direction string  // "", "all", "ingress", "egress"
	Layer     string  // "", "all", or a layer name — exact match on BlockedAtLayer
	APIKeyID  string  // "", "all", or exact match on APIKeyID
	Query     string  // "", case-insensitive substring match against Excerpt + ID
	MinRisk   float64 // events with RiskScore < MinRisk are excluded
	Before    string  // "" (start from newest), or an event ID — resume strictly after it (exclusive cursor)
	Limit     int     // page size; <=0 or >500 clamps to the default (100)
}

const (
	defaultQueryLimit = 100
	maxQueryLimit     = 500
)

// Query returns a filtered, cursor-paginated page of events, newest-first.
//
// nextCursor is the last returned event's ID when (and only when) more matching
// events exist beyond this page; it is "" otherwise. hasMore is true iff at least
// one more matching event exists after the page cutoff. A Before cursor that is
// not found in the buffer (e.g. evicted by the ring's capacity cap, or bogus)
// degrades to "start from newest" rather than erroring.
func (s *Store) Query(opts QueryOptions) (events []PromptEvent, nextCursor string, hasMore bool) {
	limit := opts.Limit
	if limit <= 0 || limit > maxQueryLimit {
		limit = defaultQueryLimit
	}
	loweredQuery := strings.ToLower(strings.TrimSpace(opts.Query))

	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.events)
	// Newest-first start index. When Before is set, find that event and resume
	// strictly after it (a lower index). If not found, start from the newest.
	start := n - 1
	if opts.Before != "" {
		for i := n - 1; i >= 0; i-- {
			if s.events[i].ID == opts.Before {
				start = i - 1
				break
			}
		}
	}

	out := make([]PromptEvent, 0, limit)
	for i := start; i >= 0; i-- {
		if !matchesQuery(&s.events[i], opts, loweredQuery) {
			continue
		}
		if len(out) >= limit {
			// One more match exists past the page boundary.
			hasMore = true
			break
		}
		out = append(out, s.events[i])
	}
	if hasMore && len(out) > 0 {
		nextCursor = out[len(out)-1].ID
	}
	return out, nextCursor, hasMore
}

// matchesQuery is the exact predicate console/lib/logs.ts's applyFilters
// implements, ported field-for-field (same "empty/all means no filter"
// convention, same substring-on-excerpt-and-id search).
func matchesQuery(e *PromptEvent, opts QueryOptions, loweredQuery string) bool {
	if !unfiltered(opts.Verdict) && e.FinalVerdict != opts.Verdict {
		return false
	}
	if !unfiltered(opts.Direction) && e.Direction != opts.Direction {
		return false
	}
	if !unfiltered(opts.Layer) && e.BlockedAtLayer != opts.Layer {
		return false
	}
	if e.RiskScore < opts.MinRisk {
		return false
	}
	if !unfiltered(opts.APIKeyID) && e.APIKeyID != opts.APIKeyID {
		return false
	}
	if loweredQuery != "" &&
		!strings.Contains(strings.ToLower(e.Excerpt), loweredQuery) &&
		!strings.Contains(strings.ToLower(e.ID), loweredQuery) {
		return false
	}
	return true
}

// unfiltered reports whether a string filter dimension means "no filter" — an
// empty value or the sentinel "all".
func unfiltered(v string) bool {
	return v == "" || v == "all"
}

// Subscribe registers a new live-tail subscriber and returns a channel of newly
// recorded events plus an unsubscribe function the caller must call exactly once
// (e.g. via defer) when done, to release the subscription. Delivery is
// best-effort: if the subscriber falls behind, Record drops frames for it rather
// than blocking the request hot path. Events recorded before Subscribe returns
// are not delivered (this is a live tail, not a replay).
func (s *Store) Subscribe() (<-chan PromptEvent, func()) {
	ch := make(chan PromptEvent, 16)
	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[chan PromptEvent]struct{})
	}
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, ch)
			close(ch)
			s.mu.Unlock()
		})
	}
	return ch, unsubscribe
}

// Summary aggregates the whole buffer into the console's DashboardSummary shape.
func (s *Store) Summary(creditsBudget int64) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	blocked := 0
	var latencySum int64
	var credits int64
	caught := map[string]int{"heuristics": 0, "ml_classifier": 0, "llm_judge": 0}
	caughtEgress := map[string]int{"pii": 0, "response_policy": 0, "response_classifier": 0, "response_judge": 0}
	for i := range s.events {
		e := &s.events[i]
		if e.FinalVerdict == "block" {
			if e.BlockedAtLayer != "" {
				if e.Direction == "egress" {
					caughtEgress[e.BlockedAtLayer]++
				} else {
					caught[e.BlockedAtLayer]++
				}
			}
		}
		// total/blocked/latency/credits describe API calls, not telemetry rows: an
		// allowed request now records both an ingress-pass event and a final event,
		// so only the terminal one counts here or these KPIs would double for every
		// call that passes ingress (see PromptEvent.terminal).
		if !e.Terminal {
			continue
		}
		total++
		if e.FinalVerdict == "block" {
			blocked++
		}
		latencySum += e.LatencyOverheadUs
		credits += int64(e.Tokens.In + e.Tokens.Out)
	}
	blockedPct := 0.0
	avgLatency := 0.0
	if total > 0 {
		blockedPct = float64(blocked) / float64(total)
		avgLatency = float64(latencySum) / float64(total)
	}
	return map[string]any{
		"totalCalls":           total,
		"blockedPct":           round(blockedPct, 4),
		"avgLatencyOverheadUs": round(avgLatency, 1),
		"creditsUsed":          credits,
		"creditsBudget":        creditsBudget,
		"caughtByLayer":        caught,
		"caughtByEgressLayer":  caughtEgress,
		"windowLabel":          "session",
	}
}

// Series buckets events by the given duration into the console's MetricPoint shape.
func (s *Store) Series(bucket time.Duration, buckets int) []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bucket <= 0 {
		bucket = time.Hour
	}
	end := s.now().UTC().Truncate(bucket).Add(bucket)
	start := end.Add(-time.Duration(buckets) * bucket)
	type agg struct {
		calls, blocked, flagged int
		latency                 int64
		credits                 int64
		byCat                   map[string]int
	}
	slots := make(map[int64]*agg)
	for i := range s.events {
		ts, err := time.Parse(time.RFC3339, s.events[i].Ts)
		if err != nil || ts.Before(start) {
			continue
		}
		key := ts.Truncate(bucket).Unix()
		a := slots[key]
		if a == nil {
			a = &agg{byCat: map[string]int{}}
			slots[key] = a
		}
		a.calls++
		switch s.events[i].FinalVerdict {
		case "block":
			a.blocked++
		case "flag":
			a.flagged++
		}
		a.latency += s.events[i].LatencyOverheadUs
		a.credits += int64(s.events[i].Tokens.In + s.events[i].Tokens.Out)
		if c := s.events[i].Category; c != "" && c != "clean" {
			a.byCat[c]++
		}
	}
	out := make([]map[string]any, 0, buckets)
	for i := 0; i < buckets; i++ {
		slotStart := start.Add(time.Duration(i) * bucket)
		a := slots[slotStart.Unix()]
		avg := 0.0
		point := map[string]any{
			"ts": slotStart.Format(time.RFC3339), "calls": 0, "blocked": 0, "flagged": 0,
			"byCategory": map[string]int{}, "avgLatencyOverheadUs": 0.0, "creditsUsed": int64(0),
		}
		if a != nil {
			if a.calls > 0 {
				avg = float64(a.latency) / float64(a.calls)
			}
			point["calls"] = a.calls
			point["blocked"] = a.blocked
			point["flagged"] = a.flagged
			point["byCategory"] = a.byCat
			point["avgLatencyOverheadUs"] = round(avg, 1)
			point["creditsUsed"] = a.credits
		}
		out = append(out, point)
	}
	return out
}

// KeyUsage returns per-API-key call and credit counts (for the ApiKey view).
func (s *Store) KeyUsage() map[string]struct {
	Calls       int
	CreditsUsed int64
	LastUsedAt  string
} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]struct {
		Calls       int
		CreditsUsed int64
		LastUsedAt  string
	}{}
	for i := range s.events {
		id := s.events[i].APIKeyID
		if id == "" {
			continue
		}
		u := out[id]
		u.Calls++
		u.CreditsUsed += int64(s.events[i].Tokens.In + s.events[i].Tokens.Out)
		if s.events[i].Ts > u.LastUsedAt {
			u.LastUsedAt = s.events[i].Ts
		}
		out[id] = u
	}
	return out
}

func round(v float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	return float64(int64(v*p+0.5)) / p
}

// SortedCategories returns category keys in stable order (for deterministic JSON).
func SortedCategories(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
