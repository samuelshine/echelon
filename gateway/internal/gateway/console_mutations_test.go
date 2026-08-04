package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/ingress"
	"github.com/jscyril/echelon/internal/keystore"
)

// fixedClassifier returns a constant malicious probability, so a test can drive
// the cascade purely by moving thresholds under it.
type fixedClassifier struct{ prob float64 }

func (f fixedClassifier) Name() string { return "ml_classifier" }
func (f fixedClassifier) Classify(context.Context, core.Prompt) (core.Classification, error) {
	return core.Classification{MaliciousProbability: f.prob}, nil
}

func okUpstream(t *testing.T) (*httptest.Server, *url.URL) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"content":"hi"}}]}`))
	}))
	u, _ := url.Parse(s.URL)
	return s, u
}

// TestConsoleCreateAuthenticateRevoke proves the full mutable-key lifecycle: a
// key created via POST /v1/console/keys returns a secret that actually
// authenticates a real /v1/chat/completions call, and DELETE causes that same
// secret to be rejected with 401.
func TestConsoleCreateAuthenticateRevoke(t *testing.T) {
	upstream, upstreamURL := okUpstream(t)
	defer upstream.Close()

	ks := keystore.NewMemoryStore(nil)
	cfg := config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20}
	handler := gateway.New(gateway.Options{
		Config:         cfg,
		KeyStore:       ks,
		Authenticator:  ks,
		UpstreamRouter: testRouter(upstreamURL.String(), "", http.DefaultTransport),
	}).Routes()

	do := func(method, path, auth, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Create.
	rec := do(http.MethodPost, "/v1/console/keys", "", `{"label":"Analytics service"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Key    map[string]any `json:"key"`
		Secret string         `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(created.Secret, "sk_live_") || len(created.Secret) != len("sk_live_")+32 {
		t.Fatalf("secret has unexpected format: %q", created.Secret)
	}
	id, _ := created.Key["id"].(string)
	if id == "" {
		t.Fatalf("create response missing key id: %v", created.Key)
	}

	chat := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"summarize my notes"}]}`

	// The returned secret authenticates a real request.
	if rec := do(http.MethodPost, "/v1/chat/completions", created.Secret, chat); rec.Code != http.StatusOK {
		t.Fatalf("authenticate with new secret: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// No credential and a bogus credential are both rejected.
	if rec := do(http.MethodPost, "/v1/chat/completions", "", chat); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: got %d, want 401", rec.Code)
	}
	if rec := do(http.MethodPost, "/v1/chat/completions", "sk_live_deadbeef", chat); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bogus key: got %d, want 401", rec.Code)
	}

	// Revoke, then the same secret must fail immediately.
	rec = do(http.MethodDelete, "/v1/console/keys/"+id, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"revoked"`) {
		t.Fatalf("revoke response should report revoked status: %s", rec.Body.String())
	}
	if rec := do(http.MethodPost, "/v1/chat/completions", created.Secret, chat); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}

	// Revoking an unknown id is a 404.
	if rec := do(http.MethodDelete, "/v1/console/keys/nope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown: got %d, want 404", rec.Code)
	}
}

// TestConsoleConfigPatchChangesCascade proves PATCH /v1/console/config both
// (a) is reflected by a subsequent GET and (b) actually changes live cascade
// behavior: a probability that passed under the old block threshold blocks under
// the new one.
func TestConsoleConfigPatchChangesCascade(t *testing.T) {
	upstream, upstreamURL := okUpstream(t)
	defer upstream.Close()

	cascade, err := ingress.NewCascade(ingress.CascadeConfig{
		HeuristicTimeout: time.Second, ClassifierTimeout: time.Second,
		JudgeThreshold: 0.55, BlockThreshold: 0.90, FailClosed: true,
	}, ingress.NewHeuristic(), fixedClassifier{prob: 0.5}, nil)
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}

	cfg := config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20, Pipeline: config.PipelineConfig{FailClosed: true}}
	handler := gateway.New(gateway.Options{
		Config:         cfg,
		Ingress:        cascade,
		UpstreamRouter: testRouter(upstreamURL.String(), "", http.DefaultTransport),
	}).Routes()

	post := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	chat := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"just a normal question"}]}`

	// prob 0.5 < block 0.9 and < judge 0.55 => allow.
	if rec := post(http.MethodPost, "/v1/chat/completions", chat); rec.Code != http.StatusOK {
		t.Fatalf("pre-patch: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Lower the block threshold (ml_classifier) below 0.5, keeping judge <= block.
	patch := `{"ingress":[{"layer":"ml_classifier","threshold":0.4},{"layer":"llm_judge","threshold":0.3}]}`
	if rec := post(http.MethodPatch, "/v1/console/config", patch); rec.Code != http.StatusOK {
		t.Fatalf("patch: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// GET reflects the new value.
	rec := post(http.MethodGet, "/v1/console/config", "")
	var got struct {
		Ingress []struct {
			Layer     string  `json:"layer"`
			Threshold float64 `json:"threshold"`
		} `json:"ingress"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	var mlThreshold float64
	for _, l := range got.Ingress {
		if l.Layer == "ml_classifier" {
			mlThreshold = l.Threshold
		}
	}
	if mlThreshold != 0.4 {
		t.Fatalf("GET after patch: ml_classifier threshold = %v, want 0.4", mlThreshold)
	}

	// Same prompt now blocks: prob 0.5 >= new block 0.4.
	if rec := post(http.MethodPost, "/v1/chat/completions", chat); rec.Code != http.StatusForbidden {
		t.Fatalf("post-patch: got %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestConsoleUpdateKeyLimits covers PATCH /v1/console/keys/{id}.
func TestConsoleUpdateKeyLimits(t *testing.T) {
	ks := keystore.NewMemoryStore(nil)
	handler := gateway.New(gateway.Options{
		Config:   config.Config{MaxRequestBytes: 1 << 20},
		KeyStore: ks,
	}).Routes()

	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	rec := do(http.MethodPost, "/v1/console/keys", `{"label":"k"}`)
	var created struct {
		Key map[string]any `json:"key"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.Key["id"].(string)

	rec = do(http.MethodPatch, "/v1/console/keys/"+id, `{"rateLimitRpm":250,"creditBudget":42000}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch key: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"rateLimitRpm":250`) || !strings.Contains(rec.Body.String(), `"creditBudget":42000`) {
		t.Fatalf("patch key response did not reflect new limits: %s", rec.Body.String())
	}

	if rec := do(http.MethodPatch, "/v1/console/keys/missing", `{"rateLimitRpm":1,"creditBudget":1}`); rec.Code != http.StatusNotFound {
		t.Fatalf("patch unknown key: got %d, want 404", rec.Code)
	}
}
