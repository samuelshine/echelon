// Package telemetry keeps a bounded, privacy-safe in-memory record of gateway
// decisions and renders them in the exact shapes the Echelon console consumes.
// No raw prompt or response text is stored — only verdicts, scores, timing, and
// identifiers.
package telemetry

import (
	"sort"
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
}

// Store is a thread-safe ring buffer of events.
type Store struct {
	mu       sync.RWMutex
	events   []PromptEvent
	capacity int
	seq      int64
	now      func() time.Time
}

func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = 5000
	}
	return &Store{capacity: capacity, now: time.Now}
}

// Record appends an event, evicting the oldest when at capacity.
func (s *Store) Record(e PromptEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Ts == "" {
		e.Ts = s.now().UTC().Format(time.RFC3339)
	}
	s.events = append(s.events, e)
	if len(s.events) > s.capacity {
		s.events = s.events[len(s.events)-s.capacity:]
	}
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

// Summary aggregates the whole buffer into the console's DashboardSummary shape.
func (s *Store) Summary(creditsBudget int64) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.events)
	blocked := 0
	var latencySum int64
	var credits int64
	caught := map[string]int{"heuristics": 0, "ml_classifier": 0, "llm_judge": 0}
	for i := range s.events {
		e := &s.events[i]
		if e.FinalVerdict == "block" {
			blocked++
			if e.BlockedAtLayer != "" {
				caught[e.BlockedAtLayer]++
			}
		}
		latencySum += e.LatencyOverheadUs
		credits += int64(e.Tokens.In + e.Tokens.Out)
	}
	blockedPct := 0.0
	avgLatency := 0.0
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100
		avgLatency = float64(latencySum) / float64(total)
	}
	return map[string]any{
		"totalCalls":           total,
		"blockedPct":           round(blockedPct, 2),
		"avgLatencyOverheadUs": round(avgLatency, 1),
		"creditsUsed":          credits,
		"creditsBudget":        creditsBudget,
		"caughtByLayer":        caught,
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
