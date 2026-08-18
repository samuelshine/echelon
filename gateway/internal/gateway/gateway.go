package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/egress"
	"github.com/jscyril/echelon/internal/guard"
	"github.com/jscyril/echelon/internal/ingress"
	"github.com/jscyril/echelon/internal/keystore"
	"github.com/jscyril/echelon/internal/observability"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/runtimeconfig"
	"github.com/jscyril/echelon/internal/telemetry"
	"github.com/jscyril/echelon/internal/upstream"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// CreditSeeder initializes a brand-new tenant's credit balance when a key is
// created from the console. The concrete ledgers differ (MemoryLedger.Credit vs
// RedisLedger.Seed), so main.go adapts whichever is active to this one-method
// interface used only by POST /v1/console/keys.
type CreditSeeder interface {
	Seed(ctx context.Context, tenantID string, amount int64) error
}

// RuntimeConfigStore persists live threshold/toggle overrides so they survive a
// restart. Nilable: when no Postgres is configured, PATCH still applies live but
// is not persisted. Load is used to merge a PATCH on top of whatever was
// previously persisted, so a request that only touches egress toggles (say)
// does not clobber a previously-saved ingress threshold override.
type RuntimeConfigStore interface {
	Load(ctx context.Context) (runtimeconfig.Overrides, bool, error)
	Save(ctx context.Context, ov runtimeconfig.Overrides) error
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
	Telemetry *telemetry.Store
	// KeyStore is the mutable API-key store backing the console keys UI (list/
	// create/update/revoke). Always wired (even when auth is disabled) so the UI
	// works; also assigned to Authenticator when auth is enabled.
	KeyStore keystore.Store
	// ConsoleAuth guards every /v1/console/* route. When nil the routes are served
	// unauthenticated, which is only reachable through an explicit opt-out in the
	// composition root (cmd/server refuses to start otherwise) or by a test
	// constructing a Gateway directly.
	ConsoleAuth ConsoleAuthenticator
	// CreditSeeder initializes a new key's tenant balance on create. Optional.
	CreditSeeder CreditSeeder
	// RuntimeConfigStore persists config overrides. Optional (nil => live-only).
	RuntimeConfigStore RuntimeConfigStore
	CreditsBudget      int64
	// Observability (Phase 6). Metrics is optional — when nil a private
	// per-instance registry is constructed so /metrics always works and the test
	// suite can build many Gateways without duplicate-registration panics.
	// TracerProvider is optional — when nil a no-op provider is used (zero
	// overhead, zero behavior change).
	Metrics        *observability.Metrics
	TracerProvider trace.TracerProvider
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
	keyStore        keystore.Store
	consoleAuth     ConsoleAuthenticator
	creditSeeder    CreditSeeder
	runtimeConfig   RuntimeConfigStore
	creditsBudget   int64
	metrics         *observability.Metrics
	tracer          trace.Tracer
}

func New(opts Options) *Gateway {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	upstreamRouter := opts.UpstreamRouter

	metrics := opts.Metrics
	if metrics == nil {
		// A private per-instance registry keeps /metrics functional while never
		// touching the global default registerer, so building many Gateways in
		// one process (the test suite) never panics on duplicate registration.
		metrics = observability.NewMetrics()
	}

	var tracer trace.Tracer
	if opts.TracerProvider != nil {
		tracer = opts.TracerProvider.Tracer("github.com/jscyril/echelon/internal/gateway")
	} else {
		tracer = noop.NewTracerProvider().Tracer("github.com/jscyril/echelon/internal/gateway")
	}

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
		keyStore:        opts.KeyStore,
		consoleAuth:     opts.ConsoleAuth,
		creditSeeder:    opts.CreditSeeder,
		runtimeConfig:   opts.RuntimeConfigStore,
		creditsBudget:   opts.CreditsBudget,
		metrics:         metrics,
		tracer:          tracer,
	}
}

func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", g.health)
	mux.HandleFunc("GET /readyz", g.ready)
	// Prometheus exposition — unauthenticated, same tier as healthz/readyz.
	mux.Handle("GET /metrics", g.metrics.Handler())
	// /admin/* is the same class as /v1/console/*: operator-only introspection of
	// how the firewall is configured. Redacted, but still a map of the defenses.
	mux.HandleFunc("GET /admin/config", g.requireConsoleAuth(g.configSummary))
	mux.HandleFunc("GET /admin/guards", g.requireConsoleAuth(g.guardSummary))
	mux.HandleFunc("POST /v1/guard/preflight", g.preflight)
	mux.HandleFunc("POST /v1/guard/output-scan", g.outputScan)
	mux.HandleFunc("GET /v1/models", g.models)
	mux.HandleFunc("POST /v1/chat/completions", g.chatCompletions)
	mux.HandleFunc("POST /v1/responses", g.responses)
	// Console operator API (B2). Every route is operator-only: these mint and
	// revoke live API keys and edit the cascade's own thresholds, so they are
	// wrapped in requireConsoleAuth rather than registered bare.
	console := g.requireConsoleAuth
	mux.HandleFunc("GET /v1/console/summary", console(g.consoleSummary))
	mux.HandleFunc("GET /v1/console/metrics", console(g.consoleMetrics))
	mux.HandleFunc("GET /v1/console/events", console(g.consoleEvents))
	mux.HandleFunc("GET /v1/console/events/stream", console(g.consoleEventsStream))
	mux.HandleFunc("GET /v1/console/keys", console(g.consoleKeysHandler))
	mux.HandleFunc("POST /v1/console/keys", console(g.consoleCreateKey))
	mux.HandleFunc("PATCH /v1/console/keys/{id}", console(g.consoleUpdateKey))
	mux.HandleFunc("DELETE /v1/console/keys/{id}", console(g.consoleRevokeKey))
	mux.HandleFunc("GET /v1/console/config", console(g.consoleConfig))
	mux.HandleFunc("PATCH /v1/console/config", console(g.consoleUpdateConfig))
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

	// One coarse root span per request, named after the route. Child spans below
	// wrap each major stage. With a no-op tracer (the default) this is free.
	ctx, span := g.tracer.Start(r.Context(), upstreamPath, trace.WithSpanKind(trace.SpanKindServer))
	span.SetAttributes(attribute.String("echelon.route", upstreamPath))
	defer span.End()
	r = r.WithContext(ctx)

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
		rlCtx, rlSpan := g.tracer.Start(r.Context(), "ratelimit.admit")
		decision, err := g.rateLimiter.Allow(rlCtx, core.RateLimit{
			Key:   g.cfg.RateLimit.KeyPrefix + key,
			Cost:  1,
			Limit: g.cfg.RateLimit.Limit,
			Burst: g.cfg.RateLimit.Burst,
			Every: g.cfg.RateLimit.Window,
		})
		if err == nil && !decision.Allowed {
			rlSpan.SetAttributes(attribute.Bool("echelon.rate_limited", true))
			rlSpan.End()
			g.metrics.RateLimitRejection()
			span.SetStatus(codes.Error, "rate_limited")
			w.Header().Set("Retry-After", retryAfterSeconds(decision.ResetAt))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "request quota exceeded")
			return
		}
		rlSpan.End()
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
			igCtx, igSpan := g.tracer.Start(r.Context(), "ingress.evaluate")
			igSpan.SetAttributes(attribute.String("echelon.direction", "ingress"))
			verdict, err := g.ingress.Evaluate(igCtx, core.Prompt{
				RequestID: r.Header.Get("X-Request-ID"), TenantID: identity.TenantID,
				APIKeyID: identity.APIKeyID, Route: upstreamPath,
				Model: extractModel(body), Text: cleanPrompt, Body: body,
			})
			if err != nil {
				igSpan.RecordError(err)
			}
			igSpan.SetAttributes(attribute.String("echelon.verdict", mapVerdict(verdict.Action)))
			igSpan.End()
			if err != nil && g.cfg.Pipeline.FailClosed {
				span.SetStatus(codes.Error, "ingress_unavailable")
				writeError(w, http.StatusForbidden, "security_unavailable", "ingress security is unavailable")
				return
			}
			// Fail closed on anything that is not an explicit allow. ActionEscalate
			// is internal to the cascade and is always resolved before Evaluate
			// returns, so reaching here with one means a bug -- and the safe
			// interpretation of "a security layer did not clear this" is to block,
			// not to forward it to the model.
			if verdict.Action != core.ActionAllow {
				span.SetStatus(codes.Error, "ingress_blocked")
				g.recordEvent(identity, verdict, start, nil, "", "ingress", true, cleanPrompt)
				writeError(w, http.StatusForbidden, findingCode(verdict, "ingress_blocked"), "prompt blocked by ingress policy")
				return
			}
			// Ingress allowed the request through. This was previously never recorded:
			// the only other recordEvent call for this request is the final one below,
			// whose `direction` gets overwritten to "egress" the moment an egress
			// pipeline is configured -- so an allowed request's ingress scan (which did
			// run: the classifier and judge were both called) never appeared in the
			// console at all. Non-terminal: the request continues past this point, so
			// it must not double-count total/blocked/latency/credits in Summary.
			g.recordEvent(identity, verdict, start, nil, "", "ingress", false, cleanPrompt)
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
			g.metrics.CreditReservation("insufficient")
			span.SetStatus(codes.Error, "insufficient_credits")
			writeError(w, http.StatusPaymentRequired, "insufficient_credits", "credit budget exhausted")
			return
		}
		g.metrics.CreditReservation("reserved")
		creditRes = res
		creditHeld = true
	}

	var resp *http.Response
	var err error
	var providerName string
	model := extractModel(body)

	// Streaming disposition. Whether the client asked for stream:true governs both
	// the safety fix (Part A) and the opt-in fast path (Part B). /v1/models is never
	// a streaming route.
	streamRequested := upstreamPath != "/v1/models" && isStreamRequested(body)
	fastMode := streamRequested && g.cfg.StreamFastMode

	// Safety fix: when the client requested streaming but fast mode is NOT active,
	// force the upstream call to be non-streaming so it returns a single, normal,
	// JSON-shaped completion. This is what makes egress ExtractAssistantText always
	// succeed and closes the stream:true egress-scan bypass. Fast mode instead
	// honors real streaming (forwards the original body) and is handled below.
	forwardBody := body
	if streamRequested && !fastMode {
		if rewritten, ok := forceNonStreaming(body); ok {
			forwardBody = rewritten
		} else {
			// Body was already validated as parseable JSON earlier in proxyLLM, so
			// this should not happen; forward the original unchanged rather than
			// erroring the request.
			g.logger.Warn("could not rewrite streaming request to non-streaming; forwarding original", "route", upstreamPath)
		}
	}

	upCtx, upSpan := g.tracer.Start(r.Context(), "upstream.forward")
	if upstreamPath == "/v1/models" {
		provider := g.upstreamRouter.DefaultProvider()
		providerName = provider.Name()
		resp, err = provider.ForwardModels(upCtx)
	} else {
		provider := g.upstreamRouter.Resolve(model)
		providerName = provider.Name()
		resp, err = provider.ForwardChat(upCtx, model, forwardBody)
	}
	upSpan.SetAttributes(attribute.String("echelon.provider", providerName))
	if err != nil {
		upSpan.RecordError(err)
		upSpan.SetStatus(codes.Error, "upstream error")
	}
	upSpan.End()

	if err != nil {
		// The upstream never produced a response, so nothing was actually charged
		// on the provider side — return the reserved credit to the tenant.
		if creditHeld {
			_ = g.creditLedger.Release(r.Context(), creditRes)
			g.metrics.CreditReservation("released")
			creditHeld = false
		}
		span.SetStatus(codes.Error, "upstream_unavailable")
		// The client-facing message must never be the raw transport error: for a
		// DNS failure, refused connection, or timeout that text names internal
		// hostnames/ports and layers Go's own error-wrapping prose on top, which
		// is neither clean nor something an end user (or even most operators) can
		// act on. It also used to be a dead end for debugging, since the raw
		// error only ever reached whichever client saw the HTTP response -- never
		// the server's own logs. Now it goes to both, in the right place: a clean
		// category to the client, the full detail to the log.
		g.logger.Error("upstream call failed", "route", upstreamPath, "provider", providerName, "error", err)
		writeError(w, http.StatusBadGateway, "upstream_unavailable", describeUpstreamError(err))
		return
	}
	defer resp.Body.Close()

	// Fast streaming path (Part B): the earlier auth/ratelimit/ingress/credit-reserve
	// setup is fully shared — only what happens from "call the upstream" onward
	// differs. streamFast reads resp.Body incrementally, enforces PII/policy at chunk
	// granularity, defers ML scanning post-hoc, and owns its own credit commit.
	if fastMode {
		g.streamFast(w, r, fastStreamParams{
			resp:         resp,
			identity:     identity,
			model:        model,
			upstreamPath: upstreamPath,
			providerName: providerName,
			requestID:    r.Header.Get("X-Request-ID"),
			start:        start,
			creditRes:    creditRes,
			creditHeld:   creditHeld,
		})
		return
	}

	// A response was received: the upstream provider actually ran the request, so
	// the tenant is charged regardless of what egress later decides.
	if creditHeld {
		_ = g.creditLedger.Commit(r.Context(), creditRes, 1)
		g.metrics.CreditReservation("committed")
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
		egCtx, egSpan := g.tracer.Start(r.Context(), "egress.scan")
		egSpan.SetAttributes(attribute.String("echelon.direction", "egress"))
		scanned, verdict, err := g.egress.Scan(egCtx, core.ModelResponse{
			RequestID: r.Header.Get("X-Request-ID"), TenantID: identity.TenantID,
			Route: upstreamPath, Model: model, Body: respBody,
		})
		if err != nil {
			egSpan.RecordError(err)
		}
		egSpan.SetAttributes(attribute.String("echelon.verdict", mapVerdict(verdict.Action)))
		egSpan.End()
		if err != nil && g.cfg.Pipeline.FailClosed {
			span.SetStatus(codes.Error, "egress_unavailable")
			writeError(w, http.StatusForbidden, "egress_unavailable", "egress security is unavailable")
			return
		}
		if verdict.Action == core.ActionBlock {
			span.SetStatus(codes.Error, "egress_blocked")
			g.recordEvent(identity, verdict, start, nil, providerName, direction, true, string(respBody))
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

	span.SetAttributes(
		attribute.String("echelon.direction", direction),
		attribute.String("echelon.final_verdict", mapVerdict(finalVerdict.Action)),
	)

	g.recordEvent(identity, finalVerdict, start, respBody, providerName, direction, true, string(respBody))

	// Safety fix (Part A) wire-correctness: the response was produced by a
	// non-streaming upstream call and fully egress-scanned above. If the original
	// client asked for streaming, deliver the scanned content as a spec-correct
	// single-chunk SSE response instead of a raw-JSON blob mislabeled as SSE. This
	// is functionally identical latency to today (still fully buffered) but safe and
	// wire-correct. Falls back to raw JSON when the body is not chat-completion
	// shaped (e.g. a non-standard /v1/responses body or an upstream error body).
	if streamRequested && g.writeSyntheticSSE(w, respBody, model) {
		return
	}

	copyResponseHeaders(w.Header(), resp.Header)
	// Egress redaction rewrites the body, so the upstream's Content-Length no longer
	// describes what we are about to send. Left uncorrected, a shortened body makes
	// the client read fewer bytes than promised and report a truncated transfer
	// (curl exit 18). We always write exactly respBody here, so state its length.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// excerpt returns what the console is allowed to see of the text a layer just
// judged. Telemetry is content-free by default -- verdicts, scores and timings
// only -- which is what makes the console safe to operate without granting
// access to user prompts. ECHELON_SHOW_EXCERPTS trades that away deliberately
// for local demos and debugging, where seeing WHICH prompt tripped a rule is
// the whole point. It is never inferred from any other setting.
func (g *Gateway) excerpt(text string) string {
	const redacted = "[redacted]"
	if !g.cfg.ShowExcerpts {
		return redacted
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return redacted
	}
	const limit = 160
	if len(trimmed) > limit {
		return trimmed[:limit] + "..."
	}
	return trimmed
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
		elapsed := time.Since(start)
		route := normalizeRoute(r.URL.Path)
		g.metrics.ObserveHTTP(route, strconv.Itoa(recorder.statusCode), elapsed)
		g.logger.Info("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.statusCode,
			"duration_ms", elapsed.Milliseconds(),
		)
	})
}

// normalizeRoute maps a request path to a bounded, low-cardinality label so the
// Prometheus route label never explodes on unknown/probed paths.
func normalizeRoute(path string) string {
	switch path {
	case "/healthz", "/readyz", "/metrics",
		"/admin/config", "/admin/guards",
		"/v1/guard/preflight", "/v1/guard/output-scan",
		"/v1/models", "/v1/chat/completions", "/v1/responses",
		"/v1/console/summary", "/v1/console/metrics", "/v1/console/events",
		"/v1/console/events/stream", "/v1/console/keys", "/v1/console/config":
		return path
	default:
		return "other"
	}
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

// describeUpstreamError turns a transport-level failure into a clean,
// user-safe category. The raw error (DNS, TCP, TLS, timeout detail, and Go's
// own wrapping prose around all of it) is logged by the caller, never
// returned here -- this is what reaches the client.
func describeUpstreamError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "the upstream language model timed out"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "the upstream language model timed out"
	}
	return "the upstream language model could not be reached"
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

func (g *Gateway) recordEvent(identity core.Identity, verdict core.Verdict, start time.Time, respBody []byte, providerName, direction string, terminal bool, scanned string) {
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
	// Emit one bounded-cardinality cascade metric per layer ruling.
	for _, l := range layers {
		g.metrics.CascadeDecision(direction, l.Layer, l.Verdict)
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
		LatencyOverheadUs: latencyUs, APIKeyID: apiKey, Excerpt: g.excerpt(scanned),
		Provider: providerName, Terminal: terminal,
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

// consoleEvents serves GET /v1/console/events with server-side filtering and
// cursor pagination.
//
// WIRE-SHAPE CHANGE: this deliberately no longer returns a bare JSON array. It now
// returns {"events":[...],"nextCursor":<id|null>,"hasMore":<bool>}. The console
// client (console/lib/api/client.ts fetchEvents/fetchEventsPage) is updated in this
// same change to consume the wrapped shape — both sides of the contract move
// together. Query params (symmetric with the camelCase JSON fields used elsewhere):
// verdict, direction, layer, apiKeyId, q, minRisk, before, limit.
func (g *Gateway) consoleEvents(w http.ResponseWriter, r *http.Request) {
	if g.telemetry == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "nextCursor": nil, "hasMore": false})
		return
	}
	q := r.URL.Query()
	minRisk, _ := strconv.ParseFloat(q.Get("minRisk"), 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	events, nextCursor, hasMore := g.telemetry.Query(telemetry.QueryOptions{
		Verdict:   q.Get("verdict"),
		Direction: q.Get("direction"),
		Layer:     q.Get("layer"),
		APIKeyID:  q.Get("apiKeyId"),
		Query:     q.Get("q"),
		MinRisk:   minRisk,
		Before:    q.Get("before"),
		Limit:     limit,
	})
	var cursor any // JSON null when there is no next page
	if nextCursor != "" {
		cursor = nextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":     events,
		"nextCursor": cursor,
		"hasMore":    hasMore,
	})
}

// consoleEventsStream serves GET /v1/console/events/stream as an SSE feed of
// newly-recorded events, driving the console's real live-tail. Best-effort: a slow
// consumer simply misses frames (the Store drops non-blocking sends to it) — it
// never slows Record. No reconnect/backoff is implemented here; the client reopens
// the EventSource when the operator re-enables live-tail.
func (g *Gateway) consoleEventsStream(w http.ResponseWriter, r *http.Request) {
	if g.telemetry == nil {
		writeError(w, http.StatusServiceUnavailable, "telemetry_unavailable", "no telemetry store configured")
		return
	}
	ch, unsubscribe := g.telemetry.Subscribe()
	defer unsubscribe()

	setSSEHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush() // establish the stream immediately, before the first event
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(data)
			_, _ = w.Write([]byte("\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// keyUsage returns the telemetry usage map, or an empty map when telemetry is
// off, so callers never nil-check.
func (g *Gateway) keyUsage() map[string]struct {
	Calls       int
	CreditsUsed int64
	LastUsedAt  string
} {
	if g.telemetry != nil {
		return g.telemetry.KeyUsage()
	}
	return map[string]struct {
		Calls       int
		CreditsUsed int64
		LastUsedAt  string
	}{}
}

// keyJSON renders one keystore.Key as the console's JSON shape, merging in
// telemetry usage. This is the single source of the list/create/update/revoke
// response shape.
func keyJSON(k keystore.Key, usage map[string]struct {
	Calls       int
	CreditsUsed int64
	LastUsedAt  string
}) map[string]any {
	u := usage[k.ID]
	key := map[string]any{
		"id": k.ID, "label": k.Label, "last4": k.Last4, "createdAt": k.CreatedAt,
		"status": k.Status, "rateLimitRpm": k.RateLimitRpm, "creditBudget": k.CreditBudget,
		"creditsUsed": u.CreditsUsed,
	}
	if u.LastUsedAt != "" {
		key["lastUsedAt"] = u.LastUsedAt
	}
	return key
}

func (g *Gateway) consoleKeysHandler(w http.ResponseWriter, r *http.Request) {
	if g.keyStore == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	keys, err := g.keyStore.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keystore_error", err.Error())
		return
	}
	usage := g.keyUsage()
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyJSON(k, usage))
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) consoleCreateKey(w http.ResponseWriter, r *http.Request) {
	if g.keyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "keystore_unavailable", "no key store configured")
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be valid JSON")
		return
	}
	label := strings.TrimSpace(body.Label)
	if label == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "label is required")
		return
	}
	key, secret, err := g.keyStore.Create(r.Context(), label, keystore.DefaultRateLimitRpm, keystore.DefaultCreditBudget)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keystore_error", err.Error())
		return
	}
	// Seed the new key's tenant so it has a spendable credit balance. Each key is
	// its own tenant (id == tenant), so seed under key.ID.
	if g.creditSeeder != nil {
		if serr := g.creditSeeder.Seed(r.Context(), key.ID, key.CreditBudget); serr != nil {
			g.logger.Warn("credit seed for new key failed", "id", key.ID, "error", serr)
		}
	}
	g.logger.Info("console key created", "id", key.ID, "label", key.Label)
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":    keyJSON(key, g.keyUsage()),
		"secret": secret,
	})
}

func (g *Gateway) consoleUpdateKey(w http.ResponseWriter, r *http.Request) {
	if g.keyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "keystore_unavailable", "no key store configured")
		return
	}
	id := r.PathValue("id")
	var body struct {
		RateLimitRpm int   `json:"rateLimitRpm"`
		CreditBudget int64 `json:"creditBudget"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be valid JSON")
		return
	}
	key, err := g.keyStore.UpdateLimits(r.Context(), id, body.RateLimitRpm, body.CreditBudget)
	if errors.Is(err, keystore.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such key")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keystore_error", err.Error())
		return
	}
	g.logger.Info("console key limits updated", "id", key.ID, "rateLimitRpm", key.RateLimitRpm, "creditBudget", key.CreditBudget)
	writeJSON(w, http.StatusOK, keyJSON(key, g.keyUsage()))
}

func (g *Gateway) consoleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if g.keyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "keystore_unavailable", "no key store configured")
		return
	}
	id := r.PathValue("id")
	key, err := g.keyStore.Revoke(r.Context(), id)
	if errors.Is(err, keystore.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such key")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keystore_error", err.Error())
		return
	}
	g.logger.Info("console key revoked", "id", key.ID)
	writeJSON(w, http.StatusOK, keyJSON(key, g.keyUsage()))
}

// liveConfig builds the /v1/console/config response from live cascade/pipeline
// state, falling back to the static env-derived values when the concrete types
// aren't wired (prototype-guards-only mode).
func (g *Gateway) liveConfig() map[string]any {
	mlThreshold := g.cfg.Pipeline.MLJudgeThreshold
	judgeThreshold := g.cfg.Pipeline.MLBlockThreshold
	if c, ok := g.ingress.(*ingress.Cascade); ok {
		// The cascade's judge threshold gates ml_classifier -> llm_judge
		// escalation; its block threshold is the ml_classifier hard-block bar.
		judge, block := c.Thresholds()
		mlThreshold = block
		judgeThreshold = judge
	}
	ingressLayers := []map[string]any{
		{"layer": "heuristics", "enabled": true, "threshold": 0.35},
		{"layer": "ml_classifier", "enabled": g.cfg.Pipeline.MLBaseURL != nil, "threshold": mlThreshold, "model": "layer2-threat-distilbert"},
		{"layer": "llm_judge", "enabled": g.cfg.Pipeline.JudgeBaseURL != nil, "threshold": judgeThreshold, "model": "claude-judge"},
	}

	pii := g.egress != nil
	policy := g.egress != nil
	classifier := g.egressMLEnabled
	if p, ok := g.egress.(*egress.Pipeline); ok {
		pii = p.ScannerEnabled("pii")
		policy = p.ScannerEnabled("response_policy")
		// response_classifier only exists when the ML cascade was wired.
		classifier = g.egressMLEnabled && p.ScannerEnabled("response_classifier")
	}

	providers := make([]string, 0)
	if g.upstreamRouter != nil {
		for name := range g.upstreamRouter.Providers() {
			providers = append(providers, name)
		}
	}
	return map[string]any{
		"ingress": ingressLayers,
		"egress": map[string]any{
			"piiMasking":        pii,
			"policyEnforcement": policy,
			"toxicityScan":      classifier,
			"maliciousCodeScan": classifier,
		},
		"providers": providers,
	}
}

func (g *Gateway) consoleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, g.liveConfig())
}

func (g *Gateway) consoleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ingress []struct {
			Layer     string   `json:"layer"`
			Threshold *float64 `json:"threshold"`
		} `json:"ingress"`
		Egress *struct {
			PIIMasking        *bool `json:"piiMasking"`
			PolicyEnforcement *bool `json:"policyEnforcement"`
			ToxicityScan      *bool `json:"toxicityScan"`
			MaliciousCodeScan *bool `json:"maliciousCodeScan"`
		} `json:"egress"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be valid JSON")
		return
	}

	// Start from whatever is already persisted (if anything) rather than a zero
	// value, so a PATCH that only touches one side (e.g. egress toggles only)
	// merges on top of a previously-saved override instead of silently erasing
	// it on the next restart. Best-effort: a load failure just starts from zero,
	// matching Save's own best-effort (warn-and-continue) failure handling below.
	var ov runtimeconfig.Overrides
	if g.runtimeConfig != nil {
		if loaded, found, err := g.runtimeConfig.Load(r.Context()); err != nil {
			g.logger.Warn("runtime config load failed", "error", err)
		} else if found {
			ov = loaded
		}
	}

	// Apply ingress thresholds. Only ml_classifier (block) and llm_judge (judge)
	// are live-mutable; heuristics is a no-op (non-editable, see design). We read
	// the current live pair and overlay whatever the request specified so a
	// single-layer edit doesn't disturb the other.
	if cascade, ok := g.ingress.(*ingress.Cascade); ok && len(body.Ingress) > 0 {
		judge, block := cascade.Thresholds()
		for _, l := range body.Ingress {
			if l.Threshold == nil {
				continue
			}
			switch l.Layer {
			case "ml_classifier":
				block = *l.Threshold
			case "llm_judge":
				judge = *l.Threshold
			default:
				// heuristics and unknown layers are accepted but ignored.
			}
		}
		if err := cascade.SetThresholds(judge, block); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_threshold", err.Error())
			return
		}
		ov.JudgeThreshold = &judge
		ov.BlockThreshold = &block
	}

	// Apply egress toggles. Skip gracefully when there is no pipeline at all.
	if body.Egress != nil {
		if p, ok := g.egress.(*egress.Pipeline); ok {
			if body.Egress.PIIMasking != nil {
				p.SetScannerEnabled("pii", *body.Egress.PIIMasking)
				ov.PIIMasking = body.Egress.PIIMasking
			}
			if body.Egress.PolicyEnforcement != nil {
				p.SetScannerEnabled("response_policy", *body.Egress.PolicyEnforcement)
				ov.PolicyEnforcement = body.Egress.PolicyEnforcement
			}
			// toxicityScan OR maliciousCodeScan both drive the single
			// response_classifier scanner (one classifier call yields both
			// verdicts). Either turning off disables it for both. When no ML
			// cascade is wired, SetScannerEnabled on an absent name is a no-op.
			var tox *bool
			if body.Egress.ToxicityScan != nil {
				tox = body.Egress.ToxicityScan
			}
			if body.Egress.MaliciousCodeScan != nil {
				// If both are present and disagree, "disabled wins" (either false
				// disables). Combine by AND.
				if tox == nil {
					tox = body.Egress.MaliciousCodeScan
				} else {
					v := *tox && *body.Egress.MaliciousCodeScan
					tox = &v
				}
			}
			if tox != nil {
				p.SetScannerEnabled("response_classifier", *tox)
				ov.ToxicityScan = tox
			}
		}
	}

	// Persist when a durable store is configured; otherwise the change is live
	// but lost on restart (honest degradation, consistent with the rest of the
	// codebase's no-Postgres behavior).
	if g.runtimeConfig != nil {
		if err := g.runtimeConfig.Save(r.Context(), ov); err != nil {
			g.logger.Warn("runtime config persist failed", "error", err)
		}
	}
	g.logger.Info("console config updated",
		"judgeThreshold", ov.JudgeThreshold, "blockThreshold", ov.BlockThreshold,
		"piiMasking", ov.PIIMasking, "policyEnforcement", ov.PolicyEnforcement, "toxicityScan", ov.ToxicityScan)

	writeJSON(w, http.StatusOK, g.liveConfig())
}

// ConsoleAuthenticator verifies the operator credential for /v1/console/*.
type ConsoleAuthenticator interface {
	VerifyConsoleToken(credential string) bool
}

// streamRouteNeedingQueryToken is the one console route a browser reaches with
// EventSource, which cannot set request headers. See requireConsoleAuth.
const streamRouteNeedingQueryToken = "/v1/console/events/stream"

// requireConsoleAuth rejects unauthenticated calls to the console operator API.
//
// A nil authenticator serves the routes open. That state is only reachable
// deliberately: cmd/server refuses to start unless CONSOLE_TOKEN is set or
// CONSOLE_AUTH_DISABLED explicitly opts out, and tests may construct a Gateway
// directly to exercise handler behaviour.
func (g *Gateway) requireConsoleAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.consoleAuth == nil {
			next(w, r)
			return
		}
		credential := r.Header.Get("Authorization")
		// EventSource cannot set headers, so the SSE route -- and only that route
		// -- also accepts the token as a query parameter. The request log records
		// r.URL.Path without the query string, so this does not reach the logs.
		// It is still the weaker path: a token in a URL is easier to leak through
		// referrers or shell history than one in a header.
		if credential == "" && r.URL.Path == streamRouteNeedingQueryToken {
			credential = r.URL.Query().Get("access_token")
		}
		if !g.consoleAuth.VerifyConsoleToken(credential) {
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"a valid console operator token is required")
			return
		}
		next(w, r)
	}
}

func corsForConsole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/console/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
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

// Flush delegates to the underlying ResponseWriter's flusher when it has one, so
// the streaming paths (which type-assert w to http.Flusher) can actually flush
// through this request-log wrapper. Embedding the http.ResponseWriter interface
// alone would not promote Flush, so it must be declared explicitly.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
