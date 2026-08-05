package gateway_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/egress"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/observability"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/prometheus/client_golang/prometheus"
)

// --- test helpers -------------------------------------------------------------

// clientWantsStream reports whether a request body sets stream:true (the fake
// upstream uses it to decide whether to answer with buffered JSON or real SSE).
func clientWantsStream(body []byte) bool {
	var p struct {
		Stream *bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Stream != nil && *p.Stream
}

// fakeUpstream models a real provider: when the inbound request is non-streaming
// it returns a single buffered JSON completion; when it is streaming it emits real
// `data: ...\n\n` SSE frames (one per chunk) with an artificial inter-chunk delay
// and a flush between each, then [DONE].
func fakeUpstream(jsonBody string, chunks []string, delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !clientWantsStream(body) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(jsonBody))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, c := range chunks {
			frame := `data: {"id":"up-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":` + strconv.Quote(c) + `}}]}` + "\n\n"
			_, _ = w.Write([]byte(frame))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(delay)
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
}

// recordingSecurity is a fake Python security service. It records the last `text`
// it was asked to classify (so a test can prove the ML classifier saw real,
// non-empty assistant text) and returns the configured malicious probability.
type recordingSecurity struct {
	mu   sync.Mutex
	text string
	prob float64
}

func (s *recordingSecurity) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.mu.Lock()
		s.text = in.Text
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"malicious_probability": s.prob})
	}))
}

func (s *recordingSecurity) recorded() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.text
}

// buildEgressPipeline mirrors main.go's buildEgress: PII + policy, plus (when
// classifyURL != nil) an ML cascade wired to a fake security service.
func buildEgressPipeline(t *testing.T, canary string, blockedTerms []string, classifyURL *url.URL) ports.EgressScanner {
	t.Helper()
	scanners := []ports.EgressScanner{
		egress.NewPIIScanner(egress.PIIMask),
		egress.NewPolicyScanner(canary, blockedTerms...),
	}
	if classifyURL != nil {
		classifier, err := egress.NewHTTPResponseClassifier("response_classifier", classifyURL, &http.Client{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("classifier: %v", err)
		}
		cascade, err := egress.NewMLCascade(egress.MLCascadeConfig{
			ClassifierTimeout: time.Second, JudgeTimeout: time.Second,
			JudgeThreshold: 0.55, BlockThreshold: 0.90,
		}, classifier, nil)
		if err != nil {
			t.Fatalf("cascade: %v", err)
		}
		scanners = append(scanners, cascade)
	}
	p, err := egress.NewPipeline(egress.PipelineConfig{FailClosed: true}, scanners...)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	return p
}

// parseSSEContent concatenates the delta.content across a client SSE response and
// reports whether a terminal [DONE] sentinel was seen and how many content-bearing
// chunks arrived.
func parseSSEContent(t *testing.T, raw string) (content string, sawDone bool, contentChunks int) {
	t.Helper()
	var b strings.Builder
	for _, event := range strings.Split(raw, "\n\n") {
		event = strings.TrimSpace(event)
		if !strings.HasPrefix(event, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(event, "data:"))
		if data == "[DONE]" {
			sawDone = true
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("client SSE frame is not valid JSON: %q (%v)", data, err)
		}
		for _, c := range chunk.Choices {
			if c.Delta.Content != "" {
				contentChunks++
				b.WriteString(c.Delta.Content)
			}
		}
	}
	return b.String(), sawDone, contentChunks
}

// flushRecorder is a ResponseWriter that counts Flush() calls so a test can
// distinguish buffered (one flush at the end) from incremental (one per chunk).
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushRecorder) Flush() { f.flushes++ }

func streamRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
}

// --- Part A: bypass closed in default (buffered) mode -------------------------

func TestDefaultModeClosesStreamBypass(t *testing.T) {
	upstream := fakeUpstream(`{"choices":[{"message":{"content":"the assistant said hello world"}}]}`, nil, 0)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	sec := &recordingSecurity{prob: 0.02}
	secServer := sec.server()
	defer secServer.Close()
	classifyURL, _ := url.Parse(secServer.URL)

	cfg := config.Config{
		UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20,
		Pipeline: config.PipelineConfig{FailClosed: true, MLTimeout: time.Second, JudgeTimeout: time.Second},
	}
	gw := gateway.New(gateway.Options{
		Config:          cfg,
		Egress:          buildEgressPipeline(t, "[CANARY]", nil, classifyURL),
		EgressMLEnabled: true,
		UpstreamRouter:  testRouter(upstreamURL.String(), "", http.DefaultTransport),
	})

	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, streamRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// The regression assertion: the classifier must have received the real, non-empty
	// assistant text. Before this phase, a stream:true request produced raw SSE that
	// ExtractAssistantText could not parse, so the classifier was handed "".
	got := sec.recorded()
	if strings.TrimSpace(got) == "" {
		t.Fatal("SECURITY BUG: classifier received empty text for a streamed request (bypass not closed)")
	}
	if !strings.Contains(got, "hello world") {
		t.Fatalf("classifier text = %q, want it to contain the real assistant reply", got)
	}

	// The client sees valid single-chunk SSE with the right content and a [DONE].
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	if cl := rec.Header().Get("Content-Length"); cl != "" {
		t.Fatalf("synthetic SSE must not set Content-Length, got %q", cl)
	}
	content, sawDone, _ := parseSSEContent(t, rec.Body.String())
	if content != "the assistant said hello world" {
		t.Fatalf("client content = %q, want the assistant reply", content)
	}
	if !sawDone {
		t.Fatal("client SSE response did not end in [DONE]")
	}
}

// Default mode must fully buffer before writing: the synthesized SSE is emitted in
// one shot with a single flush, unlike fast mode's per-chunk flushing.
func TestDefaultModeIsBufferedSingleFlush(t *testing.T) {
	upstream := fakeUpstream(`{"choices":[{"message":{"content":"buffered reply"}}]}`, nil, 0)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	cfg := config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20}
	gw := gateway.New(gateway.Options{
		Config:         cfg,
		Egress:         buildEgressPipeline(t, "[CANARY]", nil, nil),
		UpstreamRouter: testRouter(upstreamURL.String(), "", http.DefaultTransport),
	})

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	gw.Routes().ServeHTTP(rec, streamRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.flushes != 1 {
		t.Fatalf("default mode flushed %d times, want exactly 1 (fully buffered)", rec.flushes)
	}
	content, _, chunks := parseSSEContent(t, rec.Body.String())
	if content != "buffered reply" || chunks != 1 {
		t.Fatalf("default mode content=%q chunks=%d, want single-chunk %q", content, chunks, "buffered reply")
	}
}

// --- Part B: fast mode --------------------------------------------------------

func fastModeGateway(t *testing.T, upstreamURL *url.URL, egressScanner ports.EgressScanner, mlEnabled bool, metrics *observability.Metrics) *gateway.Gateway {
	t.Helper()
	cfg := config.Config{
		UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20, StreamFastMode: true,
		Pipeline: config.PipelineConfig{FailClosed: true, MLTimeout: 2 * time.Second, JudgeTimeout: 2 * time.Second},
	}
	return gateway.New(gateway.Options{
		Config:          cfg,
		Egress:          egressScanner,
		EgressMLEnabled: mlEnabled,
		Metrics:         metrics,
		UpstreamRouter:  testRouter(upstreamURL.String(), "", http.DefaultTransport),
	})
}

func TestFastModeRedactsPII(t *testing.T) {
	// The credit card sits entirely within one chunk. Cross-chunk-boundary pattern
	// matching is a known, accepted limitation of chunk-granularity scanning and is
	// deliberately not tested here.
	upstream := fakeUpstream("", []string{"your card is ", "4242424242424242", " thanks"}, 15*time.Millisecond)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	gw := fastModeGateway(t, upstreamURL, buildEgressPipeline(t, "[CANARY]", nil, nil), false, nil)

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	gw.Routes().ServeHTTP(rec, streamRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	content, sawDone, _ := parseSSEContent(t, rec.Body.String())
	if strings.Contains(content, "4242424242424242") {
		t.Fatalf("fast mode leaked an unredacted card: %q", content)
	}
	if !strings.Contains(content, "[REDACTED_CARD]") {
		t.Fatalf("fast mode did not redact the card, content=%q", content)
	}
	if !sawDone {
		t.Fatal("fast SSE stream did not end in [DONE]")
	}
	if rec.flushes < 3 {
		t.Fatalf("fast mode flushed %d times, want >= 3 (genuine incremental delivery)", rec.flushes)
	}
}

func TestFastModePolicyBlockTruncates(t *testing.T) {
	upstream := fakeUpstream("", []string{"benign start ", "leaking TOPSECRET now", "apple should never arrive"}, 15*time.Millisecond)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	gw := fastModeGateway(t, upstreamURL, buildEgressPipeline(t, "[CANARY]", []string{"TOPSECRET"}, nil), false, nil)

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	gw.Routes().ServeHTTP(rec, streamRequest())

	content, _, _ := parseSSEContent(t, rec.Body.String())
	if strings.Contains(content, "apple should never arrive") {
		t.Fatalf("fast mode kept forwarding after a policy block: %q", content)
	}
	if !strings.Contains(content, "truncated by Echelon") {
		t.Fatalf("fast mode did not emit a truncation notice, content=%q", content)
	}
	if !strings.Contains(content, "benign start") {
		t.Fatalf("fast mode dropped content that arrived before the block: %q", content)
	}
}

func TestFastModeDeferredMLFlagIsRecorded(t *testing.T) {
	upstream := fakeUpstream("", []string{"looks ", "totally ", "benign"}, 15*time.Millisecond)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	// The classifier flags the full accumulated text after the fact (prob >= block).
	sec := &recordingSecurity{prob: 0.99}
	secServer := sec.server()
	defer secServer.Close()
	classifyURL, _ := url.Parse(secServer.URL)

	reg := prometheus.NewRegistry()
	metrics := observability.NewMetricsWithRegistry(reg)
	gw := fastModeGateway(t, upstreamURL, buildEgressPipeline(t, "[CANARY]", nil, classifyURL), true, metrics)

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	gw.Routes().ServeHTTP(rec, streamRequest())

	// (a) The client received the complete streamed content — nothing was blocked
	// client-side, proving the real fast-mode tradeoff.
	content, sawDone, _ := parseSSEContent(t, rec.Body.String())
	if content != "looks totally benign" {
		t.Fatalf("client content = %q, want the full streamed text", content)
	}
	if !sawDone {
		t.Fatal("client SSE stream did not end in [DONE]")
	}
	if strings.Contains(content, "truncated") {
		t.Fatalf("fast mode must not truncate on a post-hoc ML flag: %q", content)
	}

	// (b) The post-hoc scan's block is recorded in Prometheus. The scan runs in a
	// detached goroutine, so poll the exposition until the counter appears.
	scrape := func() string {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		mrec := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(mrec, req)
		return mrec.Body.String()
	}
	deadline := time.Now().Add(3 * time.Second)
	want := `echelon_cascade_decisions_total{direction="egress",layer="response_classifier",verdict="block"} 1`
	for time.Now().Before(deadline) {
		if strings.Contains(scrape(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("post-hoc ML block was never recorded in metrics; scrape:\n%s", scrape())
}
