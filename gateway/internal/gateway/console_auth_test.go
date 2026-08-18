package gateway_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/egress"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/keystore"
)

const operatorToken = "op-secret-token"

func consoleAuthHandler(t *testing.T) http.Handler {
	t.Helper()
	consoleAuth, err := auth.NewConsoleTokenAuthenticator(operatorToken)
	if err != nil {
		t.Fatalf("build console authenticator: %v", err)
	}
	ks := keystore.NewMemoryStore(nil)
	return gateway.New(gateway.Options{
		Config:      config.Config{MaxRequestBytes: 1 << 20},
		KeyStore:    ks,
		ConsoleAuth: consoleAuth,
	}).Routes()
}

// TestConsoleRoutesRejectUnauthenticated is the regression test for the finding
// that every /v1/console/* route was served with no authentication at all --
// including the ones that mint live API keys and edit the security cascade's own
// thresholds. Each route must reject a caller with no credential.
func TestConsoleRoutesRejectUnauthenticated(t *testing.T) {
	handler := consoleAuthHandler(t)

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/v1/console/summary", ""},
		{http.MethodGet, "/v1/console/metrics", ""},
		{http.MethodGet, "/v1/console/events", ""},
		{http.MethodGet, "/v1/console/events/stream", ""},
		{http.MethodGet, "/v1/console/keys", ""},
		{http.MethodPost, "/v1/console/keys", `{"label":"attacker"}`},
		{http.MethodPatch, "/v1/console/keys/abc", `{"rateLimitRpm":100000}`},
		{http.MethodDelete, "/v1/console/keys/abc", ""},
		{http.MethodGet, "/v1/console/config", ""},
		{http.MethodPatch, "/v1/console/config", `{"mlBlockThreshold":0.99}`},
		// Same operator tier: redacted, but still a map of how the firewall is set up.
		{http.MethodGet, "/admin/config", ""},
		{http.MethodGet, "/admin/guards", ""},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401 (body=%s)",
				route.method, route.path, rec.Code, rec.Body.String())
		}
	}
}

// TestConsoleKeyMintingRequiresOperatorToken pins the specific escalation the
// missing middleware allowed: minting a live API key without any credential.
func TestConsoleKeyMintingRequiresOperatorToken(t *testing.T) {
	handler := consoleAuthHandler(t)

	mint := func(credential string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/console/keys",
			strings.NewReader(`{"label":"Analytics service"}`))
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := mint(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credential: got %d, want 401", rec.Code)
	}
	if rec := mint("wrong-token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: got %d, want 401", rec.Code)
	}
	if rec := mint(operatorToken); rec.Code != http.StatusCreated {
		t.Fatalf("operator token: got %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestTenantAPIKeyCannotReachConsole is the authorization boundary that matters
// most: a valid tenant API key authenticates the proxied LLM API, and must not
// also authorize operator actions.
func TestTenantAPIKeyCannotReachConsole(t *testing.T) {
	consoleAuth, err := auth.NewConsoleTokenAuthenticator(operatorToken)
	if err != nil {
		t.Fatalf("build console authenticator: %v", err)
	}
	ks := keystore.NewMemoryStore(nil)
	created, secret, err := ks.Create(t.Context(), "tenant key", 0, 0)
	if err != nil {
		t.Fatalf("seed tenant key: %v", err)
	}
	if created.ID == "" || secret == "" {
		t.Fatalf("keystore returned an empty key/secret")
	}
	handler := gateway.New(gateway.Options{
		Config:        config.Config{MaxRequestBytes: 1 << 20},
		KeyStore:      ks,
		Authenticator: ks,
		ConsoleAuth:   consoleAuth,
	}).Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/console/keys", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tenant key on console API: got %d, want 401 (body=%s)",
			rec.Code, rec.Body.String())
	}
}

// TestConsoleStreamAcceptsQueryToken covers the documented EventSource carve-out:
// the browser cannot set headers on an SSE subscription, so that one route also
// accepts the token as a query parameter. No other route does.
func TestConsoleStreamAcceptsQueryToken(t *testing.T) {
	handler := consoleAuthHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/console/events?access_token="+operatorToken, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query token on a non-stream route: got %d, want 401", rec.Code)
	}
}

// TestConsoleAuthRejectsEmptyToken proves a blank credential can never be
// configured into an accept-anything authenticator.
func TestConsoleAuthRejectsEmptyToken(t *testing.T) {
	for _, token := range []string{"", "   "} {
		if _, err := auth.NewConsoleTokenAuthenticator(token); err == nil {
			t.Errorf("token %q: expected an error, got nil", token)
		}
	}
}

// TestRedactedResponseHasCorrectContentLength pins a bug the demo surfaced: egress
// PII masking rewrites the response body, but the upstream's Content-Length was
// copied through unchanged. A shortened body then makes the client read fewer bytes
// than promised and report a truncated transfer (curl exit 18). It went unnoticed
// because this scenario used to be blocked outright rather than delivered.
func TestRedactedResponseHasCorrectContentLength(t *testing.T) {
	secret := `{"id":"cmpl","choices":[{"message":{"role":"assistant","content":"Reach Jane at jane.roe@example.com or on 123-45-6789."}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(secret)))
		_, _ = io.WriteString(w, secret)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	pipeline, err := egress.NewPipeline(egress.PipelineConfig{}, egress.NewPIIScanner(egress.PIIMask))
	if err != nil {
		t.Fatalf("build egress pipeline: %v", err)
	}
	handler := gateway.New(gateway.Options{
		Config:         config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20},
		Egress:         pipeline,
		UpstreamRouter: testRouter(upstreamURL.String(), "", http.DefaultTransport),
	}).Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contact"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "jane.roe@example.com") || strings.Contains(body, "123-45-6789") {
		t.Fatalf("PII survived redaction: %s", body)
	}
	declared := rec.Header().Get("Content-Length")
	if declared == "" {
		t.Fatal("no Content-Length on a fully-buffered response")
	}
	if want := strconv.Itoa(len(body)); declared != want {
		t.Errorf("Content-Length %s does not match the %s bytes actually written", declared, want)
	}
}
