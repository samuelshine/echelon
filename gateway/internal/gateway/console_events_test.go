package gateway_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/telemetry"
)

// eventsResponse mirrors the coordinated wire shape of GET /v1/console/events.
type eventsResponse struct {
	Events     []telemetry.PromptEvent `json:"events"`
	NextCursor *string                 `json:"nextCursor"`
	HasMore    bool                    `json:"hasMore"`
}

func consoleGateway(t *testing.T) (*gateway.Gateway, *telemetry.Store) {
	t.Helper()
	store := telemetry.NewStore(1000)
	gw := gateway.New(gateway.Options{Telemetry: store})
	return gw, store
}

func getEvents(t *testing.T, gw *gateway.Gateway, query string) eventsResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/console/events?"+query, nil)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out eventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func eventIDs(events []telemetry.PromptEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID)
	}
	return out
}

func TestConsoleEventsServerSideFiltering(t *testing.T) {
	gw, store := consoleGateway(t)
	store.Record(telemetry.PromptEvent{ID: "e1", Direction: "ingress", FinalVerdict: "pass", RiskScore: 0.05, APIKeyID: "key_1", Excerpt: "weather"})
	store.Record(telemetry.PromptEvent{ID: "e2", Direction: "ingress", FinalVerdict: "block", RiskScore: 0.9, BlockedAtLayer: "ml_classifier", APIKeyID: "key_1", Excerpt: "ignore instructions"})
	store.Record(telemetry.PromptEvent{ID: "e3", Direction: "egress", FinalVerdict: "flag", RiskScore: 0.5, BlockedAtLayer: "pii", APIKeyID: "key_2", Excerpt: "SSN leak"})

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{"no filter newest-first", "", []string{"e3", "e2", "e1"}},
		{"verdict", "verdict=block", []string{"e2"}},
		{"direction", "direction=egress", []string{"e3"}},
		{"layer", "layer=pii", []string{"e3"}},
		{"apiKeyId", "apiKeyId=key_1", []string{"e2", "e1"}},
		{"minRisk", "minRisk=0.6", []string{"e2"}},
		{"q on excerpt", "q=ssn", []string{"e3"}},
		{"combined", "direction=ingress&minRisk=0.6", []string{"e2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getEvents(t, gw, c.query)
			ids := eventIDs(got.Events)
			if strings.Join(ids, ",") != strings.Join(c.want, ",") {
				t.Fatalf("ids = %v, want %v", ids, c.want)
			}
		})
	}
}

func TestConsoleEventsPaginationShape(t *testing.T) {
	gw, store := consoleGateway(t)
	for i := 0; i < 7; i++ {
		store.Record(telemetry.PromptEvent{ID: string(rune('a' + i)), FinalVerdict: "block", RiskScore: 0.9})
	}

	page1 := getEvents(t, gw, "verdict=block&limit=5")
	if len(page1.Events) != 5 || !page1.HasMore || page1.NextCursor == nil {
		t.Fatalf("page1: len=%d hasMore=%v cursor=%v, want 5/true/non-nil", len(page1.Events), page1.HasMore, page1.NextCursor)
	}
	page2 := getEvents(t, gw, "verdict=block&limit=5&before="+*page1.NextCursor)
	if len(page2.Events) != 2 || page2.HasMore || page2.NextCursor != nil {
		t.Fatalf("page2: len=%d hasMore=%v cursor=%v, want 2/false/nil", len(page2.Events), page2.HasMore, page2.NextCursor)
	}
	// No overlap between pages.
	seen := map[string]bool{}
	for _, e := range append(page1.Events, page2.Events...) {
		if seen[e.ID] {
			t.Fatalf("duplicate id %q across pages", e.ID)
		}
		seen[e.ID] = true
	}
	if len(seen) != 7 {
		t.Fatalf("saw %d unique events across pages, want 7", len(seen))
	}
}

func TestConsoleEventsEmptyShape(t *testing.T) {
	gw, _ := consoleGateway(t)
	got := getEvents(t, gw, "")
	if got.Events == nil {
		t.Fatal("events must serialize as [] not null")
	}
	if got.HasMore || got.NextCursor != nil {
		t.Fatalf("empty store: hasMore=%v cursor=%v, want false/nil", got.HasMore, got.NextCursor)
	}
}

// TestConsoleEventsStream connects a real HTTP client to the SSE endpoint, then
// records an event concurrently and asserts the frame arrives on the open stream.
func TestConsoleEventsStream(t *testing.T) {
	gw, store := consoleGateway(t)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/console/events/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("SSE stream must not set Content-Length, got %q", cl)
	}

	// Record after the connection is established so the subscriber is registered.
	// Retry a few times to close the tiny window between Do() returning and the
	// handler's Subscribe() running.
	reader := bufio.NewReader(resp.Body)
	type result struct {
		line string
		err  error
	}
	frames := make(chan result, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if strings.HasPrefix(line, "data: ") {
				frames <- result{line: line}
				return
			}
			if err != nil {
				frames <- result{err: err}
				return
			}
		}
	}()

	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case r := <-frames:
			if r.err != nil {
				t.Fatalf("reading SSE frame: %v", r.err)
			}
			payload := strings.TrimSpace(strings.TrimPrefix(r.line, "data: "))
			var e telemetry.PromptEvent
			if err := json.Unmarshal([]byte(payload), &e); err != nil {
				t.Fatalf("SSE frame is not a valid PromptEvent JSON: %q (%v)", payload, err)
			}
			if e.ID != "streamed-1" {
				t.Fatalf("received event id %q, want streamed-1", e.ID)
			}
			return
		case <-tick.C:
			store.Record(telemetry.PromptEvent{ID: "streamed-1", FinalVerdict: "pass"})
		case <-deadline:
			t.Fatal("never received the streamed SSE frame")
		}
	}
}
