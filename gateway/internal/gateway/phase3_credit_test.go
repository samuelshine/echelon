package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/credit"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
)

func creditTestGateway(t *testing.T, upstreamURL *url.URL, ledger ports.CreditLedger) http.Handler {
	t.Helper()
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
	return gateway.New(gateway.Options{
		Config: cfg, Authenticator: authn, RateLimiter: limiter, CreditLedger: ledger,
		UpstreamRouter: testRouter(cfg.UpstreamBaseURL.String(), cfg.UpstreamAPIKey, http.DefaultTransport),
	}).Routes()
}

func postChat(handler http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer sk-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestCreditExhaustedReturns402: a tenant starting at 0 credits is denied with 402.
func TestCreditExhaustedReturns402(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	ledger := credit.NewMemoryLedger(map[string]int64{"acme": 0})
	handler := creditTestGateway(t, upstreamURL, ledger)

	rec := postChat(handler)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d, want 402 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "insufficient_credits") {
		t.Fatalf("expected insufficient_credits code, body=%s", rec.Body.String())
	}
}

// TestSuccessfulRequestDecrementsBalanceByOne: a completed request commits exactly
// 1 credit (reserve 1, commit actual 1, no refund).
func TestSuccessfulRequestDecrementsBalanceByOne(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"message":{"content":"hi"}}]}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	ledger := credit.NewMemoryLedger(map[string]int64{"acme": 5})
	handler := creditTestGateway(t, upstreamURL, ledger)

	if rec := postChat(handler); rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := ledger.Balance("acme"); got != 4 {
		t.Fatalf("balance after one request = %d, want 4", got)
	}
	// Second request depletes further, deterministically.
	if rec := postChat(handler); rec.Code != http.StatusOK {
		t.Fatalf("second request got %d, want 200", rec.Code)
	}
	if got := ledger.Balance("acme"); got != 3 {
		t.Fatalf("balance after two requests = %d, want 3", got)
	}
}

// TestUpstreamFailureReleasesCredit: when the upstream never returns a response,
// the reserved credit is released (not charged).
func TestUpstreamFailureReleasesCredit(t *testing.T) {
	// Point at a closed listener so ForwardChat errors without a response.
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL, _ := url.Parse(upstream.URL)
	upstream.Close() // now unreachable

	ledger := credit.NewMemoryLedger(map[string]int64{"acme": 5})
	handler := creditTestGateway(t, upstreamURL, ledger)

	if rec := postChat(handler); rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rec.Code)
	}
	if got := ledger.Balance("acme"); got != 5 {
		t.Fatalf("balance after failed upstream = %d, want 5 (credit must be released)", got)
	}
}
