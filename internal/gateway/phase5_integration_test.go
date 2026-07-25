package gateway_test

import (
	"encoding/json"
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
	"github.com/jscyril/echelon/internal/ingress"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
)

// fakeSecurity emulates the Python service: /classify and /judge in the exact
// JSON the Go adapters decode with DisallowUnknownFields.
func fakeSecurity() *httptest.Server {
	mux := http.NewServeMux()
	readText := func(r *http.Request) string {
		var in struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		return in.Text
	}
	mux.HandleFunc("/classify", func(w http.ResponseWriter, r *http.Request) {
		prob := 0.02
		if strings.Contains(readText(r), "flagme") {
			prob = 0.99
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"malicious_probability": prob})
	})
	mux.HandleFunc("/judge", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"malicious": false, "confidence": 0.5, "code": "uncertain_context"})
	})
	return httptest.NewServer(mux)
}

func buildTestGateway(t *testing.T, upstream *url.URL, security *url.URL, burst int64) *gateway.Gateway {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	classifier, err := ingress.NewHTTPClassifier("ml", security.JoinPath("classify"), client)
	if err != nil {
		t.Fatalf("classifier: %v", err)
	}
	judge, err := ingress.NewHTTPJudge("judge", security.JoinPath("judge"), client)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	cascade, err := ingress.NewCascade(ingress.CascadeConfig{
		HeuristicTimeout: time.Second, ClassifierTimeout: time.Second, JudgeTimeout: time.Second,
		JudgeThreshold: 0.55, BlockThreshold: 0.90, FailClosed: true,
	}, ingress.NewHeuristic(), classifier, judge)
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	authn, err := auth.NewStaticAPIKeyAuthenticator(map[string]core.Identity{
		"sk-test": {TenantID: "acme", APIKeyID: "k1", Plan: "pro"},
	})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	cfg := config.Config{
		UpstreamBaseURL: upstream,
		MaxRequestBytes: 1 << 20,
		Pipeline:        config.PipelineConfig{FailClosed: true},
		RateLimit:       config.RateLimitConfig{Backend: "memory", Limit: 60, Burst: burst, Window: time.Minute, KeyPrefix: "rl:"},
	}
	var limiter ports.RateLimiter = ratelimit.NewMemoryTokenBucket()
	return gateway.New(gateway.Options{
		Config: cfg, Ingress: cascade, Authenticator: authn, RateLimiter: limiter,
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	})
}

func TestPhase5EndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"content":"hi"}}]}`))
	}))
	defer upstream.Close()
	security := fakeSecurity()
	defer security.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	securityURL, _ := url.Parse(security.URL)

	handler := buildTestGateway(t, upstreamURL, securityURL, 100).Routes()

	post := func(auth, text string) *httptest.ResponseRecorder {
		body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"` + text + `"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("", "hello"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: got %d, want 401", rec.Code)
	}
	if rec := post("sk-test", "please summarize my notes"); rec.Code != http.StatusOK {
		t.Fatalf("benign: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := post("sk-test", "please flagme now"); rec.Code != http.StatusForbidden {
		t.Fatalf("classifier-flagged: got %d, want 403", rec.Code)
	}
}

func TestPhase5RateLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	security := fakeSecurity()
	defer security.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	securityURL, _ := url.Parse(security.URL)
	handler := buildTestGateway(t, upstreamURL, securityURL, 1).Routes()

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer sk-test")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("second request (burst=1): got %d, want 429", code)
	}
}
