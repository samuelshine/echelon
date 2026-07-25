package gateway

import (
	"bytes"
	"context"
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
)

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Options struct {
	Config        config.Config
	Logger        *slog.Logger
	Guards        guard.PromptGuard
	OutputScanner guard.OutputScanner
	HTTPClient    HTTPDoer
	// Hexagonal security composition (Phases 4-5). When Ingress is set it replaces
	// the prototype Guards on the proxied OpenAI path; Authenticator/RateLimiter are
	// enforced when present.
	Ingress       ports.IngressLayer
	Egress        ports.EgressScanner
	Authenticator ports.Authenticator
	RateLimiter   ports.RateLimiter
}

type Gateway struct {
	cfg           config.Config
	logger        *slog.Logger
	guards        guard.PromptGuard
	outputScanner guard.OutputScanner
	httpClient    HTTPDoer
	ingress       ports.IngressLayer
	egress        ports.EgressScanner
	authenticator ports.Authenticator
	rateLimiter   ports.RateLimiter
}

func New(opts Options) *Gateway {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}

	return &Gateway{
		cfg:           opts.Config,
		logger:        logger,
		guards:        opts.Guards,
		outputScanner: opts.OutputScanner,
		httpClient:    httpClient,
		ingress:       opts.Ingress,
		egress:        opts.Egress,
		authenticator: opts.Authenticator,
		rateLimiter:   opts.RateLimiter,
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
	return g.withRequestLog(mux)
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
	g.proxyOpenAI(w, r, "/v1/models")
}

func (g *Gateway) chatCompletions(w http.ResponseWriter, r *http.Request) {
	g.proxyOpenAI(w, r, "/v1/chat/completions")
}

func (g *Gateway) responses(w http.ResponseWriter, r *http.Request) {
	g.proxyOpenAI(w, r, "/v1/responses")
}

func (g *Gateway) proxyOpenAI(w http.ResponseWriter, r *http.Request, upstreamPath string) {
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

	upstreamReq, err := g.newUpstreamRequest(r.Context(), r, upstreamPath, body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_request_failed", err.Error())
		return
	}

	resp, err := g.httpClient.Do(upstreamReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_unavailable", err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := readLimited(resp.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_response_too_large", err.Error())
		return
	}

	// Egress: hexagonal scanner pipeline when wired (may redact), else prototype scanner.
	if g.egress != nil {
		scanned, verdict, err := g.egress.Scan(r.Context(), core.ModelResponse{Body: respBody})
		if err != nil && g.cfg.Pipeline.FailClosed {
			writeError(w, http.StatusForbidden, "egress_unavailable", "egress security is unavailable")
			return
		}
		if verdict.Action == core.ActionBlock {
			writeError(w, http.StatusForbidden, findingCode(verdict, "egress_blocked"), "response blocked by egress policy")
			return
		}
		if verdict.Action == core.ActionRedact && scanned.Body != nil {
			respBody = scanned.Body
		}
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

func (g *Gateway) newUpstreamRequest(ctx context.Context, inbound *http.Request, path string, body []byte) (*http.Request, error) {
	target := *g.cfg.UpstreamBaseURL
	target.Path = joinURLPath(g.cfg.UpstreamBaseURL.Path, path)
	target.RawQuery = inbound.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, inbound.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	copyRequestHeaders(req.Header, inbound.Header)
	req.Host = target.Host
	if g.cfg.UpstreamAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.UpstreamAPIKey)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Del("Content-Length")
	return req, nil
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
