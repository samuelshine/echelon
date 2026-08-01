package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/guard"
)

// The unauthenticated /metrics route must exist, return 200 with a Prometheus
// text content type, and expose the gateway's metric families.
func TestMetricsEndpoint(t *testing.T) {
	upstreamURL, _ := url.Parse("https://llm.example")
	gw := New(Options{
		Config: config.Config{
			UpstreamBaseURL: upstreamURL,
			MaxRequestBytes: 1024,
			UpstreamTimeout: time.Second,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Guards: guard.NewChain(guard.NewInjectionFilter()),
		UpstreamRouter: testRouter(upstreamURL.String(), "", roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"id":"ok","usage":{"prompt_tokens":1,"completion_tokens":2}}`)),
			}, nil
		})),
	})

	// Drive one proxied request so counters have data to expose.
	proxyReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	gw.Routes().ServeHTTP(httptest.NewRecorder(), proxyReq)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("/metrics content-type = %q, want text/plain*", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"echelon_http_requests_total",
		"echelon_http_request_duration_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q", want)
		}
	}
}

// Constructing many Gateways in one test binary (as the suite does) must not
// panic on duplicate metric registration — each gets a private registry.
func TestMultipleGatewaysNoRegistrationPanic(t *testing.T) {
	upstreamURL, _ := url.Parse("https://llm.example")
	for i := 0; i < 5; i++ {
		_ = New(Options{
			Config: config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1024},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}
}
