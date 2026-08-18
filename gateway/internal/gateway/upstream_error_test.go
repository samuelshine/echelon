package gateway_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/keystore"
)

// TestUpstreamUnavailableReportsACleanMessage is the regression test for a
// second instance of the same class of bug fixed in policy_assistant/llm.py:
// the client-facing error for a transport-level upstream failure used to be
// the raw Go error (err.Error()) -- for a timeout that includes internal
// wrapping prose like "context deadline exceeded (Client.Timeout exceeded
// while awaiting headers)", and for a DNS/connection failure it can name
// internal hostnames or ports. Neither is something an end user should see,
// and the raw detail previously went ONLY to the client -- the server's own
// logs recorded nothing beyond a bare 502 status line, so there was no way to
// debug the failure from the server side at all.
func TestUpstreamUnavailableReportsACleanMessage(t *testing.T) {
	// A server slower than the client's deadline forces a real client-side
	// timeout, the same failure mode a slow provider produces, without relying
	// on DNS behaving a particular way in CI. The delay is bounded (not a block
	// on ctx.Done) so httptest.Close, which waits for outstanding handlers,
	// cannot hang the test run.
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"message":{"content":"late"}}]}`))
	}))
	defer hang.Close()
	upstreamURL, err := url.Parse(hang.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	ks := keystore.NewMemoryStore(nil)
	handler := gateway.New(gateway.Options{
		Config: config.Config{
			UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20,
			UpstreamTimeout: 50 * time.Millisecond,
		},
		Logger:         logger,
		KeyStore:       ks,
		UpstreamRouter: testRouter(hang.URL, "", timeoutTransport{50 * time.Millisecond}),
	}).Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// The client must see a clean category, never Go's raw transport error text.
	if strings.Contains(body, "context deadline exceeded") || strings.Contains(body, "Client.Timeout") {
		t.Errorf("raw transport error leaked to the client: %s", body)
	}
	if !strings.Contains(body, "the upstream language model timed out") {
		t.Errorf("client response missing the clean timeout message: %s", body)
	}

	// The full detail must still be recoverable server-side -- that's the
	// other half of the fix: debugging a real outage can't depend on whatever
	// client happened to be connected when it occurred.
	logged := logBuf.String()
	if !strings.Contains(logged, "upstream call failed") {
		t.Errorf("server log missing the upstream failure entry: %s", logged)
	}
	if !strings.Contains(logged, "context deadline exceeded") {
		t.Errorf("server log should retain the real error detail, got: %s", logged)
	}
}

// timeoutTransport forces a hard client-side deadline on every round trip,
// producing a real context.DeadlineExceeded the same way a slow or
// unreachable provider would in production.
type timeoutTransport struct{ timeout time.Duration }

func (t timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
	defer cancel()
	return http.DefaultTransport.RoundTrip(req.WithContext(ctx))
}
