package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jscyril/echelon/internal/auth"
	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/credit"
	"github.com/jscyril/echelon/internal/egress"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/guard"
	"github.com/jscyril/echelon/internal/ingress"
	"github.com/jscyril/echelon/internal/keystore"
	"github.com/jscyril/echelon/internal/observability"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
	"github.com/jscyril/echelon/internal/runtimeconfig"
	"github.com/jscyril/echelon/internal/telemetry"
	"github.com/jscyril/echelon/internal/upstream"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"time"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	filterChain := guard.NewChain(
		guard.NewTokenLimitFilter(cfg.MaxRequestBytes),
		guard.NewPIIFilter(),
		guard.NewInjectionFilter(),
	)

	outputScanner := guard.NewOutputScanner(cfg.SystemCanary)

	// Hexagonal security composition. The ingress cascade (heuristics -> remote ML
	// classifier -> remote LLM judge) is wired when ML_BASE_URL is configured; it
	// then supersedes the prototype guards on the proxied OpenAI path.
	startupCtx := context.Background()
	securityClient := &http.Client{Timeout: cfg.Pipeline.JudgeTimeout + cfg.Pipeline.MLTimeout}
	ingressCascade := buildIngress(cfg, securityClient, logger)
	egressPipeline, egressMLEnabled := buildEgress(cfg, securityClient, logger)

	// Mutable API-key store (Phase 5). Seeded once from ECHELON_API_KEYS, then the
	// single source of truth for both request auth and the console keys UI.
	// Postgres-backed when AUDIT_DATABASE_URL is set (survives restarts), else an
	// in-process memory store (frictionless local dev). Auth turns on whenever
	// ECHELON_API_KEYS was set OR Postgres is configured (a real deployment) —
	// the latter gives a clean from-zero bootstrap: point at Postgres with no keys,
	// auth turns on with an empty store, and the operator creates the first key
	// from the console.
	seedKeys := parseSeedKeys(cfg)
	authEnabled := strings.TrimSpace(os.Getenv("ECHELON_API_KEYS")) != "" || cfg.AuditDatabaseURL != ""
	var keyStore keystore.Store
	if cfg.AuditDatabaseURL != "" {
		ps, kerr := keystore.NewPostgresStore(startupCtx, cfg.AuditDatabaseURL, seedKeys)
		if kerr != nil {
			logger.Error("postgres key store init failed", "error", kerr)
			os.Exit(1)
		}
		keyStore = ps
		defer ps.Close()
		logger.Info("postgres key store enabled", "keys_seeded", len(seedKeys))
	} else {
		keyStore = keystore.NewMemoryStore(seedKeys)
		logger.Info("in-memory key store enabled", "keys_seeded", len(seedKeys))
	}
	var authenticator ports.Authenticator
	if authEnabled {
		authenticator = keyStore
		logger.Info("api-key auth enabled")
	} else {
		logger.Info("api-key auth disabled (no ECHELON_API_KEYS and no AUDIT_DATABASE_URL)")
	}

	// Credit seed derives from the same key list: each seeded key is its own
	// tenant (id == tenant), seeded to its budget. Matches the pre-Phase-5 seed.
	creditSeed := map[string]int64{}
	for _, sk := range seedKeys {
		creditSeed[sk.Key.ID] = sk.Key.CreditBudget
	}

	// Rate limiter + credit ledger share a single backend flag (RATE_LIMIT_BACKEND):
	// "redis" wires both against one shared *redis.Client; "memory" (the default)
	// wires the in-process adapters. There is deliberately no separate CREDIT_BACKEND
	// in this phase — one flag governs both distributed adapters.
	var rateLimiter ports.RateLimiter
	var creditLedger ports.CreditLedger
	var creditSeeder gateway.CreditSeeder
	switch cfg.RateLimit.Backend {
	case "redis":
		opts, err := redis.ParseURL(cfg.RateLimit.RedisURL)
		if err != nil {
			logger.Error("invalid REDIS_URL", "error", err)
			os.Exit(1)
		}
		client := redis.NewClient(opts)
		rateLimiter = ratelimit.NewRedisTokenBucket(client)
		ledger, err := credit.NewRedisLedger(client, creditSeed, 0)
		if err != nil {
			logger.Error("failed to seed redis credit ledger", "error", err)
			os.Exit(1)
		}
		creditLedger = ledger
		creditSeeder = ledger // *RedisLedger already has Seed(ctx, tenant, amount).
		logger.Info("redis rate limiter + credit ledger enabled", "tenants_seeded", len(creditSeed))
	default: // "memory"
		rateLimiter = ratelimit.NewMemoryTokenBucket()
		ledger := credit.NewMemoryLedger(creditSeed)
		creditLedger = ledger
		creditSeeder = memSeeder{ledger} // adapts MemoryLedger.Credit to the seeder interface.
		logger.Info("in-memory rate limiter + credit ledger enabled", "tenants_seeded", len(creditSeed))
	}

	// OpenTelemetry tracing. Driven entirely by the standard OTEL_* env vars; with
	// no OTLP endpoint configured this is a no-op provider (zero overhead).
	tracerProvider, shutdownTracer, err := observability.InitTracer(context.Background())
	if err != nil {
		logger.Error("otel tracer init failed; continuing without tracing", "error", err)
	}
	otel.SetTracerProvider(tracerProvider)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracer(shutdownCtx)
	}()

	telemetryStore := telemetry.NewStore(5000)

	// Durable audit sink (optional). When AUDIT_DATABASE_URL is set, persist
	// events to Postgres and hydrate the ring from the most recent rows so a
	// restart doesn't show an empty console. Unset → in-memory only (no dep).
	var auditSink *telemetry.PostgresSink
	if cfg.AuditDatabaseURL != "" {
		sink, serr := telemetry.NewPostgresSink(context.Background(), cfg.AuditDatabaseURL)
		if serr != nil {
			logger.Error("audit postgres sink disabled", "error", serr)
		} else {
			auditSink = sink
			if recent, herr := sink.Recent(context.Background(), telemetryStore.Capacity()); herr != nil {
				logger.Warn("audit hydrate failed", "error", herr)
			} else {
				telemetryStore.Hydrate(recent)
				logger.Info("audit ring hydrated from postgres", "events", len(recent))
			}
			defer sink.Close()
		}
	}

	// Runtime-config overrides (Phase 5). Shares AUDIT_DATABASE_URL with the audit
	// sink and key store. Persisted threshold/toggle changes are loaded and applied
	// to the live cascade/pipeline BEFORE the server accepts traffic, so an operator
	// override survives a restart. Unset Postgres => overrides apply live but are
	// lost on restart (honest degradation, noted in docs).
	var runtimeStore gateway.RuntimeConfigStore
	if cfg.AuditDatabaseURL != "" {
		rc, rerr := runtimeconfig.NewStore(startupCtx, cfg.AuditDatabaseURL)
		if rerr != nil {
			logger.Error("runtime config store disabled", "error", rerr)
		} else {
			runtimeStore = rc
			defer rc.Close()
			if ov, ok, lerr := rc.Load(startupCtx); lerr != nil {
				logger.Warn("runtime config load failed", "error", lerr)
			} else if ok {
				applyOverrides(ingressCascade, egressPipeline, egressMLEnabled, ov, logger)
				logger.Info("runtime config overrides applied from postgres")
			}
		}
	}

	consoleAuth, err := buildConsoleAuth(cfg, logger)
	if err != nil {
		logger.Error("console auth misconfigured", "error", err)
		os.Exit(1)
	}

	app := gateway.New(gateway.Options{
		Config:             cfg,
		Logger:             logger,
		Guards:             filterChain,
		OutputScanner:      outputScanner,
		Ingress:            ingressCascade,
		Egress:             egressPipeline,
		EgressMLEnabled:    egressMLEnabled,
		Authenticator:      authenticator,
		RateLimiter:        rateLimiter,
		CreditLedger:       creditLedger,
		Telemetry:          telemetryStore,
		KeyStore:           keyStore,
		ConsoleAuth:        consoleAuth,
		CreditSeeder:       creditSeeder,
		RuntimeConfigStore: runtimeStore,
		CreditsBudget:      1_000_000,
		UpstreamRouter:     buildProviderRouter(cfg, logger),
		TracerProvider:     tracerProvider,
	})

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           app.Routes(),
		ReadHeaderTimeout: cfg.ReadTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Drain the telemetry ring's durable-sink channel until shutdown. No-op when
	// no sink was configured.
	if auditSink != nil {
		telemetryStore.RunSink(ctx, auditSink, logger)
	}

	go func() {
		logger.Info("echelon gateway listening", "addr", cfg.Address)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

// buildProviderRouter creates the multi-provider router from configuration.
func buildProviderRouter(cfg config.Config, logger *slog.Logger) *upstream.Router {
	client := &http.Client{Timeout: cfg.UpstreamTimeout}
	var providers []upstream.Provider

	if p, err := upstream.NewOpenAI(upstream.ProviderConfig{
		Name:    "openai",
		BaseURL: cfg.Providers.OpenAI.BaseURL,
		APIKey:  cfg.Providers.OpenAI.APIKey,
	}, client); err == nil {
		providers = append(providers, p)
	}

	if cfg.Providers.Gemini.BaseURL != "" {
		if p, err := upstream.NewGemini(upstream.ProviderConfig{
			Name:    "gemini",
			BaseURL: cfg.Providers.Gemini.BaseURL,
			APIKey:  cfg.Providers.Gemini.APIKey,
		}, client); err == nil {
			providers = append(providers, p)
		}
	}

	if cfg.Providers.Anthropic.BaseURL != "" {
		if p, err := upstream.NewAnthropic(upstream.ProviderConfig{
			Name:    "anthropic",
			BaseURL: cfg.Providers.Anthropic.BaseURL,
			APIKey:  cfg.Providers.Anthropic.APIKey,
		}, client); err == nil {
			providers = append(providers, p)
		}
	}

	if cfg.Providers.Ollama.BaseURL != "" {
		if p, err := upstream.NewOllama(upstream.ProviderConfig{
			Name:    "ollama",
			BaseURL: cfg.Providers.Ollama.BaseURL,
			APIKey:  cfg.Providers.Ollama.APIKey,
		}, client); err == nil {
			providers = append(providers, p)
		}
	}

	router, err := upstream.NewRouter(providers, upstream.RouterConfig{
		ModelRoutes:     cfg.Providers.ModelRoutes,
		DefaultProvider: cfg.Providers.DefaultProvider,
	})
	if err != nil {
		logger.Error("failed to construct upstream router", "error", err)
		os.Exit(1)
	}

	logger.Info("multi-provider routing enabled", "providers", len(providers))
	return router
}

// buildIngress assembles the heuristics -> remote ML classifier -> remote judge
// cascade. It returns nil (prototype guards remain in effect) when ML_BASE_URL is
// unset, so local development without the Python security service still works.
func buildIngress(cfg config.Config, client *http.Client, logger *slog.Logger) ports.IngressLayer {
	if cfg.Pipeline.MLBaseURL == nil {
		logger.Info("ingress cascade disabled (no ML_BASE_URL); using prototype guards")
		return nil
	}
	classifier, err := ingress.NewHTTPClassifier("ml_classifier", cfg.Pipeline.MLBaseURL, client)
	if err != nil {
		logger.Error("classifier adapter build failed; falling back to prototype guards", "error", err)
		return nil
	}
	var judge ports.PromptJudge
	if cfg.Pipeline.JudgeBaseURL != nil {
		if j, jerr := ingress.NewHTTPJudge("llm_judge", cfg.Pipeline.JudgeBaseURL, client); jerr == nil {
			judge = j
		} else {
			logger.Error("judge adapter build failed; cascade will fail-to-escalate", "error", jerr)
		}
	}
	cascade, err := ingress.NewCascade(ingress.CascadeConfig{
		HeuristicTimeout:  cfg.Pipeline.HeuristicTimeout,
		ClassifierTimeout: cfg.Pipeline.MLTimeout,
		JudgeTimeout:      cfg.Pipeline.JudgeTimeout,
		JudgeThreshold:    cfg.Pipeline.MLJudgeThreshold,
		BlockThreshold:    cfg.Pipeline.MLBlockThreshold,
		FailClosed:        cfg.Pipeline.FailClosed,
	}, ingress.NewHeuristic(), classifier, judge)
	if err != nil {
		logger.Error("ingress cascade build failed; falling back to prototype guards", "error", err)
		return nil
	}
	logger.Info("ingress cascade enabled", "ml_base_url", cfg.Pipeline.MLBaseURL.String(), "judge_wired", judge != nil)
	return cascade
}

// buildEgress assembles the always-on PII/policy scanners plus the optional
// ML classifier -> judge cascade (mirrors buildIngress; wired when
// EGRESS_ML_BASE_URL is set). Returns (pipeline, mlEnabled) — mlEnabled tells
// the console whether toxicity/malicious-code scanning is genuinely wired,
// so /v1/console/config never has to guess or hardcode.
func buildEgress(cfg config.Config, client *http.Client, logger *slog.Logger) (ports.EgressScanner, bool) {
	scanners := []ports.EgressScanner{
		egress.NewPIIScanner(egress.PIIMask),
		egress.NewPolicyScanner(cfg.SystemCanary),
	}
	mlEnabled := false
	if cfg.Pipeline.EgressMLBaseURL != nil {
		classifier, err := egress.NewHTTPResponseClassifier("response_classifier", cfg.Pipeline.EgressMLBaseURL, client)
		if err != nil {
			logger.Error("egress response classifier build failed; toxicity/malicious-code scanning disabled", "error", err)
		} else {
			var judge *egress.HTTPResponseJudge
			if cfg.Pipeline.EgressJudgeBaseURL != nil {
				j, jerr := egress.NewHTTPResponseJudge("response_judge", cfg.Pipeline.EgressJudgeBaseURL, client)
				if jerr != nil {
					logger.Error("egress response judge build failed; cascade will fail-to-escalate", "error", jerr)
				} else {
					judge = j
				}
			}
			cascade, cerr := egress.NewMLCascade(egress.MLCascadeConfig{
				ClassifierTimeout: cfg.Pipeline.MLTimeout, JudgeTimeout: cfg.Pipeline.JudgeTimeout,
				JudgeThreshold: cfg.Pipeline.MLJudgeThreshold, BlockThreshold: cfg.Pipeline.MLBlockThreshold,
			}, classifier, judge)
			if cerr != nil {
				logger.Error("egress ML cascade build failed; toxicity/malicious-code scanning disabled", "error", cerr)
			} else {
				scanners = append(scanners, cascade)
				mlEnabled = true
			}
		}
	}
	pipeline, err := egress.NewPipeline(egress.PipelineConfig{
		ScannerTimeout: cfg.Pipeline.EgressTimeout, FailClosed: cfg.Pipeline.FailClosed,
	}, scanners...)
	if err != nil {
		logger.Error("egress pipeline build failed; responses will not be scanned", "error", err)
		return nil, false
	}
	logger.Info("egress pipeline enabled", "ml_wired", mlEnabled)
	return pipeline, mlEnabled
}

// parseSeedKeys parses ECHELON_API_KEYS ("key:tenant:keyid:plan,...") into the
// bootstrap seed for the key store — the single replacement for the three
// separately-parsed copies of this env var that existed before Phase 5
// (buildAuthenticator + buildConsoleKeys + buildCreditSeed).
//
// Backward-compat note: a seeded key's TenantID stays parts[1] (the tenant), so
// existing keys keep billing to the same tenant. Because the PostgresStore has
// no tenant column and derives Identity{TenantID,APIKeyID} = key.ID, the seeded
// key's ID is set to parts[1] so that derivation preserves the tenant. The
// MemoryStore honors the full legacy Identity verbatim (keeping parts[2] keyid /
// parts[3] plan for the zero-Postgres dev path). Only newly created console keys
// use the pure per-key-tenant scheme (id == tenant == apiKeyId).
func parseSeedKeys(cfg config.Config) []keystore.SeedKey {
	raw := strings.TrimSpace(os.Getenv("ECHELON_API_KEYS"))
	if raw == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var seed []keystore.SeedKey
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		secret := parts[0]
		tenant := parts[1]
		last4 := secret
		if len(secret) > 4 {
			last4 = secret[len(secret)-4:]
		}
		identity := core.Identity{TenantID: tenant, APIKeyID: tenant}
		if len(parts) > 2 && parts[2] != "" {
			identity.APIKeyID = parts[2]
		}
		if len(parts) > 3 {
			identity.Plan = parts[3]
		}
		seed = append(seed, keystore.SeedKey{
			Secret: secret,
			Key: keystore.Key{
				ID: tenant, Label: tenant, Last4: last4, CreatedAt: now, Status: "active",
				RateLimitRpm: int(cfg.RateLimit.Limit), CreditBudget: keystore.DefaultCreditBudget,
			},
			Identity: identity,
		})
	}
	return seed
}

// memSeeder adapts *credit.MemoryLedger (whose Credit(tenant, amount) takes no
// ctx and returns no error) to gateway.CreditSeeder, so POST /v1/console/keys can
// seed a new key's balance the same way regardless of the ledger backend.
type memSeeder struct{ l *credit.MemoryLedger }

func (m memSeeder) Seed(_ context.Context, tenantID string, amount int64) error {
	m.l.Credit(tenantID, amount)
	return nil
}

// applyOverrides applies persisted runtime-config overrides to the live cascade
// and egress pipeline at startup, before the server accepts traffic. Nil/absent
// concrete types are skipped gracefully (prototype-guards-only / no-egress modes).
func applyOverrides(ingressLayer ports.IngressLayer, egressScanner ports.EgressScanner, egressMLEnabled bool, ov runtimeconfig.Overrides, logger *slog.Logger) {
	if cascade, ok := ingressLayer.(*ingress.Cascade); ok && (ov.JudgeThreshold != nil || ov.BlockThreshold != nil) {
		judge, block := cascade.Thresholds()
		if ov.JudgeThreshold != nil {
			judge = *ov.JudgeThreshold
		}
		if ov.BlockThreshold != nil {
			block = *ov.BlockThreshold
		}
		if err := cascade.SetThresholds(judge, block); err != nil {
			logger.Warn("persisted threshold override rejected", "error", err)
		}
	}
	if pipeline, ok := egressScanner.(*egress.Pipeline); ok {
		if ov.PIIMasking != nil {
			pipeline.SetScannerEnabled("pii", *ov.PIIMasking)
		}
		if ov.PolicyEnforcement != nil {
			pipeline.SetScannerEnabled("response_policy", *ov.PolicyEnforcement)
		}
		if ov.ToxicityScan != nil && egressMLEnabled {
			pipeline.SetScannerEnabled("response_classifier", *ov.ToxicityScan)
		}
	}
}

// buildConsoleAuth resolves the operator credential guarding /v1/console/*.
//
// Fail-closed: those routes mint and revoke live API keys and edit the security
// cascade's own thresholds, so an unset credential is a startup error rather
// than a permissive default. CONSOLE_AUTH_DISABLED=true is the explicit opt-out
// for local development, and it announces itself loudly in the log so an
// unauthenticated console can never be reached by accident or inherited from a
// stale environment.
func buildConsoleAuth(cfg config.Config, logger *slog.Logger) (gateway.ConsoleAuthenticator, error) {
	if cfg.ConsoleAuth.Token != "" {
		return auth.NewConsoleTokenAuthenticator(cfg.ConsoleAuth.Token)
	}
	if cfg.ConsoleAuth.Disabled {
		logger.Warn("console operator API is UNAUTHENTICATED",
			"reason", "CONSOLE_AUTH_DISABLED=true",
			"impact", "anyone who can reach this gateway can mint API keys and change security thresholds",
			"fix", "set CONSOLE_TOKEN")
		return nil, nil
	}
	return nil, fmt.Errorf(
		"CONSOLE_TOKEN is required: /v1/console/* can mint API keys and change security thresholds. " +
			"Set CONSOLE_TOKEN, or set CONSOLE_AUTH_DISABLED=true to serve it unauthenticated for local development")
}
