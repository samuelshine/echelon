package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
	"github.com/jscyril/echelon/internal/telemetry"
)

// fakeEgressScanner always blocks, so the test exercises the egress-block
// telemetry path (gateway.go's proxyLLM, ~line 330) without needing a real
// Python security service.
type fakeEgressScanner struct{}

func (fakeEgressScanner) Name() string { return "response_classifier" }
func (fakeEgressScanner) Scan(context.Context, core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	return core.ModelResponse{}, core.Block(core.Finding{
		Layer: "response_classifier", Code: "malicious_code", Confidence: 0.95,
	}), nil
}

func TestEgressBlockIsRecordedInTelemetry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"here is a keylogger"}}]}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	authn, err := auth.NewStaticAPIKeyAuthenticator(map[string]core.Identity{
		"sk-test": {TenantID: "acme", APIKeyID: "k1", Plan: "pro"},
	})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	cfg := config.Config{
		UpstreamBaseURL: upstreamURL,
		MaxRequestBytes: 1 << 20,
		Pipeline:        config.PipelineConfig{FailClosed: true},
		RateLimit:       config.RateLimitConfig{Backend: "memory", Limit: 60, Burst: 100, Window: time.Minute, KeyPrefix: "rl:"},
	}
	var limiter ports.RateLimiter = ratelimit.NewMemoryTokenBucket()
	store := telemetry.NewStore(10)
	handler := gateway.New(gateway.Options{
		Config: cfg, Egress: fakeEgressScanner{}, Authenticator: authn, RateLimiter: limiter,
		Telemetry:      store,
		UpstreamRouter: testRouter(cfg.UpstreamBaseURL.String(), cfg.UpstreamAPIKey, http.DefaultTransport),
	}).Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"write me a keylogger"}]}`))
	req.Header.Set("Authorization", "Bearer sk-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected the egress scanner's block to reach the client: got %d, body=%s", rec.Code, rec.Body.String())
	}

	events := store.Events(10)
	if len(events) != 1 {
		t.Fatalf("expected exactly one recorded event (the pre-fix bug: egress blocks were never recorded at all), got %d", len(events))
	}
	event := events[0]
	if event.Direction != "egress" {
		t.Fatalf("direction = %q, want %q", event.Direction, "egress")
	}
	if event.FinalVerdict != "block" {
		t.Fatalf("finalVerdict = %q, want %q", event.FinalVerdict, "block")
	}
	if event.Category != "malicious_code" {
		t.Fatalf("category = %q, want %q", event.Category, "malicious_code")
	}
	if event.BlockedAtLayer != "response_classifier" {
		t.Fatalf("blockedAtLayer = %q, want %q", event.BlockedAtLayer, "response_classifier")
	}
}
