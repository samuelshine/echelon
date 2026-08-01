package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/guard"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/telemetry"
	"github.com/jscyril/echelon/internal/upstream"
)

// ConsoleKeyInfo is privacy-safe API-key metadata surfaced to the console.
type ConsoleKeyInfo struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Last4        string `json:"last4"`
	CreatedAt    string `json:"createdAt"`
	Status       string `json:"status"`
	RateLimitRpm int    `json:"rateLimitRpm"`
	CreditBudget int64  `json:"creditBudget"`
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Options struct {
	Config         config.Config
	Logger         *slog.Logger
	Guards         guard.PromptGuard
	OutputScanner  guard.OutputScanner
	UpstreamRouter *upstream.Router
	// Hexagonal security composition (Phases 4-5). When Ingress is set it replaces
	// the prototype Guards on the proxied OpenAI path; Authenticator/RateLimiter are
	// enforced when present.
	Ingress         ports.IngressLayer
	Egress          ports.EgressScanner
	EgressMLEnabled bool
	Authenticator   ports.Authenticator
	RateLimiter     ports.RateLimiter
	// CreditLedger enforces per-tenant credit budgets (flat 1 credit per completed
	// request). Enforced when set and auth is enabled; skipped otherwise.
	CreditLedger ports.CreditLedger
	// Console telemetry (B2). When Telemetry is set, decisions are recorded and the
	// /v1/console/* read API is served.
	Telemetry     *telemetry.Store
	ConsoleKeys   []ConsoleKeyInfo
	CreditsBudget int64
}

type Gateway struct {
	cfg             config.Config
	logger          *slog.Logger
	guards          guard.PromptGuard
	outputScanner   guard.OutputScanner
	upstreamRouter  *upstream.Router
	ingress         ports.IngressLayer
	egress          ports.EgressScanner
	egressMLEnabled bool
	authenticator   ports.Authenticator
	rateLimiter     ports.RateLimiter
	creditLedger    ports.CreditLedger
	telemetry       *telemetry.Store
	consoleKeys     []ConsoleKeyInfo
	creditsBudget   int64
}

func New(opts Options) *Gateway {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	upstreamRouter := opts.UpstreamRouter

	return &Gateway{
		cfg:             opts.Config,
		logger:          logger,
		guards:          opts.Guards,
		outputScanner:   opts.OutputScanner,
		upstreamRouter:  upstreamRouter,
		ingress:         opts.Ingress,
		egress:          opts.Egress,
		egressMLEnabled: opts.EgressMLEnabled,
		authenticator:   opts.Authenticator,
		rateLimiter:     opts.RateLimiter,
		creditLedger:    opts.CreditLedger,
		telemetry:       opts.Telemetry,
		consoleKeys:     opts.ConsoleKeys,
		creditsBudget:   opts.CreditsBudget,
	}
}

func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", g.health)
	mux.HandleFunc("GET /readyz", g.ready)
	mux.HandleFunc("GET /admin/config", g.configSummary)
	mux.HandleFunc("GET /admin/guards", g.guardSummary)
	mux.HandleFunc("POST /v1/guard/preflight", g.preflight)
	mux.HandleFunc("POST /v1/guard/output-scan", g.outputScan)
	mux.HandleFunc("GET /v1/models", g.models)
	mux.HandleFunc("POST /v1/chat/completions", g.chatCompletions)
	mux.HandleFunc("POST /v1/responses", g.responses)
	// Console read API (B2).
	mux.HandleFunc("GET /v1/console/summary", g.consoleSummary)
	mux.HandleFunc("GET /v1/console/metrics", g.consoleMetrics)
	mux.HandleFunc("GET /v1/console/events", g.consoleEvents)
	mux.HandleFunc("GET /v1/console/keys", g.consoleKeysHandler)
	mux.HandleFunc("GET /v1/console/config", g.consoleConfig)
	return corsForConsole(g.withRequestLog(mux))
}

func (g *Gateway) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"name":   "echelon",
	})
}

func (g *Gateway) ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                  "ready",
		"upstream_base_url":       g.cfg.UpstreamBaseURL.String(),
		"upstream_key_configured": g.cfg.UpstreamAPIKey != "",
		"max_request_bytes":       g.cfg.MaxRequestBytes,
		"guards":                  g.promptGuardNames(),
		"output_scanners":         g.outputScannerNames(),
	})
}

func (g *Gateway) configSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"http_addr":                g.cfg.Address,
		"upstream_base_url":        g.cfg.UpstreamBaseURL.String(),
		"upstream_key_configured":  g.cfg.UpstreamAPIKey != "",
		"max_request_bytes":        g.cfg.MaxRequestBytes,
		"upstream_timeout":         g.cfg.UpstreamTimeout.String(),
		"system_canary_configured": g.cfg.SystemCanary != "",
		"log_level":                g.cfg.LogLevel.String(),
	})
}

func (g *Gateway) guardSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"prompt_guards":   g.promptGuardNames(),
		"output_scanners": g.outputScannerNames(),
	})
}

func (g *Gateway) preflight(w http.ResponseWriter, r *http.Request) {
	body, err := readLimited(r.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", err.Error())
		return
	}

	promptText, err := extractPromptText(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	decision := guard.Allow()
	if g.guards != nil {
		decision = g.guards.Check(r.Context(), guard.PromptRequest{
			Route: "/v1/guard/preflight",
			Body:  body,
			Text:  promptText,
		})
	}

	writeJSON(w, statusFromDecision(decision), map[string]any{
		"allowed":    decision.Allowed,
		"decision":   decision,
		"text_bytes": len(promptText),
		"guards":     g.promptGuardNames(),
	})
}

func (g *Gateway) outputScan(w http.ResponseWriter, r *http.Request) {
	body, err := readLimited(r.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", err.Error())
		return
	}

	decision := guard.Allow()
	if g.outputScanner != nil {
		decision = g.outputScanner.Scan(r.Context(), guard.OutputResponse{
			Route: "/v1/guard/output-scan",
			Body:  body,
		})
	}

	writeJSON(w, statusFromDecision(decision), map[string]any{
		"allowed":         decision.Allowed,
		"decision":        decision,
		"response_bytes":  len(body),
		"output_scanners": g.outputScannerNames(),
	})
}

func (g *Gateway) models(w http.ResponseWriter, r *http.Request) {
	g.proxyLLM(w, r, "/v1/models")
}

func (g *Gateway) chatCompletions(w http.ResponseWriter, r *http.Request) {
	g.proxyLLM(w, r, "/v1/chat/completions")
}

func (g *Gateway) responses(w http.ResponseWriter, r *http.Request) {
	g.proxyLLM(w, r, "/v1/responses")
}

func (g *Gateway) proxyLLM(w http.ResponseWriter, r *http.Request, upstreamPath string) {
	start := time.Now()
	body := []byte(nil)
	if r.Body != nil {
		var err error
		body, err = readLimited(r.Body, g.cfg.MaxRequestBytes)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", err.Error())
			return
		}
	}

	// Authentication (enforced when an authenticator is configured).
	var identity core.Identity
	if g.authenticator != nil {
		id, err := g.authenticator.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid API key is required")
			return
		}
		identity = id
	}

	// Rate/quota admission (enforced when a limiter is configured).
	if g.rateLimiter != nil {
		key := identity.APIKeyID
		if key == "" {
			key = clientIP(r)
		}
		decision, err := g.rateLimiter.Allow(r.Context(), core.RateLimit{
			Key:   g.cfg.RateLimit.KeyPrefix + key,
			Cost:  1,
			Limit: g.cfg.RateLimit.Limit,
			Burst: g.cfg.RateLimit.Burst,
			Every: g.cfg.RateLimit.Window,
		})
		if err == nil && !decision.Allowed {
			w.Header().Set("Retry-After", retryAfterSeconds(decision.ResetAt))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "request quota exceeded")
			return
		}
	}

	// Ingress security: the hexagonal cascade when wired, else the prototype guards.
	if len(body) > 0 {
		promptText, err := extractPromptText(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if g.ingress != nil {
			// The ML classifier should score the user prompt, not role labels/model id.
			cleanPrompt := extractChatPrompt(body)
			if cleanPrompt == "" {
				cleanPrompt = promptText
			}
			verdict, err := g.ingress.Evaluate(r.Context(), core.Prompt{
				RequestID: r.Header.Get("X-Request-ID"), TenantID: identity.TenantID,
				APIKeyID: identity.APIKeyID, Route: upstreamPath,
				Model: extractModel(body), Text: cleanPrompt, Body: body,
			})
			if err != nil && g.cfg.Pipeline.FailClosed {
				writeError(w, http.StatusForbidden, "security_unavailable", "ingress security is unavailable")
				return
			}
			if verdict.Action == core.ActionBlock {
				g.recordEvent(identity, verdict, start, nil, "", "ingress")
				writeError(w, http.StatusForbidden, findingCode(verdict, "ingress_blocked"), "prompt blocked by ingress policy")
				return
			}
		} else if g.guards != nil {
			decision := g.guards.Check(r.Context(), guard.PromptRequest{Route: upstreamPath, Body: body, Text: promptText})
			if !decision.Allowed {
				writeError(w, http.StatusForbidden, decision.Code, decision.Message)
				return
			}
		}
	}

	// Credit enforcement (flat 1 credit per completed request). Reserved here —
	// after rate-limit and ingress have admitted the request — so a request blocked
	// upstream of this point never touches credits. Released below if the upstream
	// call never completes; committed once a response is received. Skipped entirely
	// when no ledger is configured or auth is disabled (there is no tenant to bill).
	var creditRes core.CreditReservation
	var creditHeld bool
	if g.creditLedger != nil && identity.TenantID != "" {
		idemKey := r.Header.Get("X-Request-ID")
		if idemKey == "" {
			idemKey = newRequestID()
		}
		res, rerr := g.creditLedger.Reserve(r.Context(), identity.TenantID, idemKey, 1)
		if rerr != nil {
			writeError(w, http.StatusPaymentRequired, "insufficient_credits", "credit budget exhausted")
			return
		}
		creditRes = res
		creditHeld = true
	}

	var resp *http.Response
	var err error
	var providerName string
	model := extractModel(body)

	if upstreamPath == "/v1/models" {
		provider := g.upstreamRouter.DefaultProvider()
		providerName = provider.Name()
		resp, err = provider.ForwardModels(r.Context())
	} else {
		provider := g.upstreamRouter.Resolve(model)
		providerName = provider.Name()
		resp, err = provider.ForwardChat(r.Context(), model, body)
	}

	if err != nil {
		// The upstream never produced a response, so nothing was actually charged
		// on the provider side — return the reserved credit to the tenant.
		if creditHeld {
			_ = g.creditLedger.Release(r.Context(), creditRes)
			creditHeld = false
		}
		writeError(w, http.StatusBadGateway, "upstream_unavailable", err.Error())
		return
	}
	defer resp.Body.Close()

	// A response was received: the upstream provider actually ran the request, so
	// the tenant is charged regardless of what egress later decides.
	if creditHeld {
		_ = g.creditLedger.Commit(r.Context(), creditRes, 1)
		creditHeld = false
	}

	respBody, err := readLimited(resp.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_response_too_large", err.Error())
		return
	}

	// Egress: hexagonal scanner pipeline when wired (may redact), else prototype scanner.
	finalVerdict := core.Allow()
	direction := "ingress"
	if g.egress != nil {
		direction = "egress"
		scanned, verdict, err := g.egress.Scan(r.Context(), core.ModelResponse{
			RequestID: r.Header.Get("X-Request-ID"), TenantID: identity.TenantID,
			Route: upstreamPath, Model: model, Body: respBody,
		})
		if err != nil && g.cfg.Pipeline.FailClosed {
			writeError(w, http.StatusForbidden, "egress_unavailable", "egress security is unavailable")
			return
		}
		if verdict.Action == core.ActionBlock {
			g.recordEvent(identity, verdict, start, nil, providerName, direction)
			writeError(w, http.StatusForbidden, findingCode(verdict, "egress_blocked"), "response blocked by egress policy")
			return
		}
		if verdict.Action == core.ActionRedact && scanned.Body != nil {
			respBody = scanned.Body
		}
		finalVerdict = verdict
	} else if g.outputScanner != nil {
		decision := g.outputScanner.Scan(r.Context(), guard.OutputResponse{
			Route: upstreamPath,
			Body:  respBody,
		})
		if !decision.Allowed {
			writeError(w, http.StatusForbidden, decision.Code, decision.Message)
			return
		}
	}

	g.recordEvent(identity, finalVerdict, start, respBody, providerName, direction)

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func (g *Gateway) promptGuardNames() []string {
	if g.guards == nil {
		return nil
	}
	named, ok := g.guards.(interface{ Names() []string })
	if ok {
		return named.Names()
	}
	single, ok := g.guards.(interface{ Name() string })
	if ok {
		return []string{single.Name()}
	}
	return []string{"unnamed"}
}

func (g *Gateway) outputScannerNames() []string {
	if g.outputScanner == nil {
		return nil
	}
	named, ok := g.outputScanner.(interface{ Name() string })
	if ok {
		return []string{named.Name()}
	}
	return []string{"unnamed"}
}

func (g *Gateway) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		g.logger.Info("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func extractPromptText(body []byte) (string, error) {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("request body must be valid JSON: %w", err)
	}

	var builder strings.Builder
	collectStrings(&builder, payload)
	return builder.String(), nil
}

func collectStrings(builder *strings.Builder, value any) {
	switch typed := value.(type) {
	case string:
		builder.WriteString(typed)
		builder.WriteByte('\n')
	case []any:
		for _, item := range typed {
			collectStrings(builder, item)
		}
	case map[string]any:
		for _, item := range typed {
			collectStrings(builder, item)
		}
	}
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("body exceeds %d bytes", limit)
	}
	return body, nil
}

func copyRequestHeaders(dst, src http.Header) {
	for key, values := range src {
		if shouldSkipHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if shouldSkipHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func shouldSkipHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func joinURLPath(basePath string, nextPath string) string {
	base := strings.TrimRight(basePath, "/")
	next := "/" + strings.TrimLeft(nextPath, "/")
	if base == "" {
		return next
	}
	return (&url.URL{Path: base + next}).EscapedPath()
}

// extractChatPrompt pulls only the user-authored prompt (message contents, input,
// or prompt) from an OpenAI-style body, so the ML classifier scores the actual
// prompt rather than a soup of role labels and the model id.
func extractChatPrompt(body []byte) string {
	var payload struct {
		Messages []struct {
			Content any `json:"content"`
		} `json:"messages"`
		Input  any `json:"input"`
		Prompt any `json:"prompt"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var b strings.Builder
	for _, m := range payload.Messages {
		writeContent(&b, m.Content)
	}
	writeContent(&b, payload.Input)
	writeContent(&b, payload.Prompt)
	return strings.TrimSpace(b.String())
}

func writeContent(b *strings.Builder, value any) {
	switch typed := value.(type) {
	case string:
		b.WriteString(typed)
		b.WriteByte('\n')
	case []any:
		for _, item := range typed {
			if part, ok := item.(map[string]any); ok {
				if text, ok := part["text"].(string); ok {
					b.WriteString(text)
					b.WriteByte('\n')
				}
				continue
			}
			writeContent(b, item)
		}
	}
}

// --- Console telemetry (B2) ---------------------------------------------------

func (g *Gateway) recordEvent(identity core.Identity, verdict core.Verdict, start time.Time, respBody []byte, providerName, direction string) {
	if g.telemetry == nil {
		return
	}
	latencyUs := time.Since(start).Microseconds()
	finalVerdict := mapVerdict(verdict.Action)
	risk := 0.0
	blockedAt := ""
	category := "clean"
	layers := make([]telemetry.LayerResult, 0, len(verdict.Findings))
	for _, f := range verdict.Findings {
		if f.Confidence > risk {
			risk = f.Confidence
		}
		layer := mapLayer(f.Layer)
		if blockedAt == "" {
			blockedAt = layer
		}
		if category == "clean" {
			category = mapCategory(layer, f.Code)
		}
		layers = append(layers, telemetry.LayerResult{
			Layer: layer, Verdict: finalVerdict, Score: round4(f.Confidence),
			Threshold: g.cfg.Pipeline.MLBlockThreshold, Model: f.Layer,
			Detail: map[string]any{"code": f.Code, "message": f.Message},
		})
	}
	if len(layers) == 0 {
		defaultLayer := "heuristics"
		if direction == "egress" {
			defaultLayer = "pii"
		}
		layers = append(layers, telemetry.LayerResult{
			Layer: defaultLayer, Verdict: "pass", Threshold: g.cfg.Pipeline.MLBlockThreshold,
			LatencyUs: latencyUs, Detail: map[string]any{},
		})
	}
	in, out := estimateTokens(respBody)
	blocked := ""
	if finalVerdict != "pass" {
		blocked = blockedAt
	}
	apiKey := identity.APIKeyID
	if apiKey == "" {
		apiKey = "anonymous"
	}
	g.telemetry.Record(telemetry.PromptEvent{
		ID: fmt.Sprintf("evt_%x", time.Now().UnixNano()), Direction: direction,
		FinalVerdict: finalVerdict, RiskScore: round4(risk), Category: category,
		BlockedAtLayer: blocked, Layers: layers, Tokens: telemetry.Tokens{In: in, Out: out},
		LatencyOverheadUs: latencyUs, APIKeyID: apiKey, Excerpt: "[redacted]",
		Provider: providerName,
	})
}

func (g *Gateway) consoleSummary(w http.ResponseWriter, _ *http.Request) {
	if g.telemetry == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, g.telemetry.Summary(g.creditsBudget))
}

func (g *Gateway) consoleMetrics(w http.ResponseWriter, _ *http.Request) {
	if g.telemetry == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, g.telemetry.Series(time.Hour, 24))
}

func (g *Gateway) consoleEvents(w http.ResponseWriter, _ *http.Request) {
	if g.telemetry == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, g.telemetry.Events(500))
}

func (g *Gateway) consoleKeysHandler(w http.ResponseWriter, _ *http.Request) {
	usage := map[string]struct {
		Calls       int
		CreditsUsed int64
		LastUsedAt  string
	}{}
	if g.telemetry != nil {
		usage = g.telemetry.KeyUsage()
	}
	out := make([]map[string]any, 0, len(g.consoleKeys))
	for _, k := range g.consoleKeys {
		u := usage[k.ID]
		key := map[string]any{
			"id": k.ID, "label": k.Label, "last4": k.Last4, "createdAt": k.CreatedAt,
			"status": k.Status, "rateLimitRpm": k.RateLimitRpm, "creditBudget": k.CreditBudget,
			"creditsUsed": u.CreditsUsed,
		}
		if u.LastUsedAt != "" {
			key["lastUsedAt"] = u.LastUsedAt
		}
		out = append(out, key)
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) consoleConfig(w http.ResponseWriter, _ *http.Request) {
	ingress := []map[string]any{
		{"layer": "heuristics", "enabled": true, "threshold": 0.35},
		{"layer": "ml_classifier", "enabled": g.cfg.Pipeline.MLBaseURL != nil, "threshold": g.cfg.Pipeline.MLJudgeThreshold, "model": "layer2-threat-distilbert"},
		{"layer": "llm_judge", "enabled": g.cfg.Pipeline.JudgeBaseURL != nil, "threshold": g.cfg.Pipeline.MLBlockThreshold, "model": "claude-judge"},
	}
	providers := make([]string, 0)
	if g.upstreamRouter != nil {
		for name := range g.upstreamRouter.Providers() {
			providers = append(providers, name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ingress": ingress,
		"egress": map[string]any{
			"piiMasking":        g.egress != nil,
			"policyEnforcement": g.egress != nil,
			"toxicityScan":      g.egressMLEnabled,
			"maliciousCodeScan": g.egressMLEnabled,
		},
		"providers": providers,
	})
}

func corsForConsole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/console/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func mapVerdict(action core.Action) string {
	switch action {
	case core.ActionBlock:
		return "block"
	case core.ActionRedact:
		return "flag"
	default:
		return "pass"
	}
}

func mapLayer(layer string) string {
	switch layer {
	case "heuristic", "heuristics", "ingress_cascade":
		return "heuristics"
	case "llm_judge", "judge":
		return "llm_judge"
	case "pii", "response_policy", "response_classifier", "response_judge":
		return layer
	default:
		return "ml_classifier"
	}
}

func mapCategory(layer, code string) string {
	if layer == "pii" {
		return "pii_leak"
	}
	c := strings.ToLower(code)
	if c == "malicious_code" {
		return "malicious_code"
	}
	switch {
	case strings.Contains(c, "leak"), strings.Contains(c, "extract"), strings.Contains(c, "exfil"):
		return "data_exfiltration"
	case strings.Contains(c, "role"), strings.Contains(c, "jailbreak"), strings.Contains(c, "dan"):
		return "jailbreak"
	case strings.Contains(c, "code"), strings.Contains(c, "malicious"), strings.Contains(c, "policy"):
		return "policy_violation"
	case strings.Contains(c, "tox"), strings.Contains(c, "harm"):
		return "toxicity"
	case strings.Contains(c, "pii"):
		return "pii_leak"
	case strings.Contains(c, "inject"), strings.Contains(c, "override"), strings.Contains(c, "delimiter"):
		return "prompt_injection"
	default:
		return "prompt_injection"
	}
}

func estimateTokens(respBody []byte) (int, int) {
	if len(respBody) > 0 {
		var payload struct {
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(respBody, &payload); err == nil && (payload.Usage.PromptTokens+payload.Usage.CompletionTokens) > 0 {
			return payload.Usage.PromptTokens, payload.Usage.CompletionTokens
		}
		return 0, len(respBody) / 4
	}
	return 0, 0
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000
}

func extractModel(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Model
}

func findingCode(verdict core.Verdict, fallback string) string {
	if len(verdict.Findings) > 0 && verdict.Findings[0].Code != "" {
		return verdict.Findings[0].Code
	}
	return fallback
}

// newRequestID mints a random idempotency key when the client sends no
// X-Request-ID, mirroring credit.newID (hex-encoded crypto/rand, no new dep).
func newRequestID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if comma := strings.IndexByte(forwarded, ','); comma >= 0 {
			return strings.TrimSpace(forwarded[:comma])
		}
		return strings.TrimSpace(forwarded)
	}
	host := r.RemoteAddr
	if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return host
}

func retryAfterSeconds(resetAt time.Time) string {
	seconds := int(time.Until(resetAt).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d", seconds)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func statusFromDecision(decision guard.Decision) int {
	if decision.Allowed {
		return http.StatusOK
	}
	return http.StatusForbidden
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
