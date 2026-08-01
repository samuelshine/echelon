package main

import (
	"context"
	"errors"
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
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
	"github.com/jscyril/echelon/internal/telemetry"
	"github.com/jscyril/echelon/internal/upstream"
	"github.com/redis/go-redis/v9"
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
	securityClient := &http.Client{Timeout: cfg.Pipeline.JudgeTimeout + cfg.Pipeline.MLTimeout}
	ingressCascade := buildIngress(cfg, securityClient, logger)
	egressPipeline, egressMLEnabled := buildEgress(cfg, securityClient, logger)
	authenticator := buildAuthenticator(logger)

	// Rate limiter + credit ledger share a single backend flag (RATE_LIMIT_BACKEND):
	// "redis" wires both against one shared *redis.Client; "memory" (the default)
	// wires the in-process adapters. There is deliberately no separate CREDIT_BACKEND
	// in this phase — one flag governs both distributed adapters.
	creditSeed := buildCreditSeed(cfg)
	var rateLimiter ports.RateLimiter
	var creditLedger ports.CreditLedger
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
		logger.Info("redis rate limiter + credit ledger enabled", "tenants_seeded", len(creditSeed))
	default: // "memory"
		rateLimiter = ratelimit.NewMemoryTokenBucket()
		creditLedger = credit.NewMemoryLedger(creditSeed)
		logger.Info("in-memory rate limiter + credit ledger enabled", "tenants_seeded", len(creditSeed))
	}

	telemetryStore := telemetry.NewStore(5000)

	app := gateway.New(gateway.Options{
		Config:          cfg,
		Logger:          logger,
		Guards:          filterChain,
		OutputScanner:   outputScanner,
		Ingress:         ingressCascade,
		Egress:          egressPipeline,
		EgressMLEnabled: egressMLEnabled,
		Authenticator:   authenticator,
		RateLimiter:     rateLimiter,
		CreditLedger:    creditLedger,
		Telemetry:       telemetryStore,
		ConsoleKeys:     buildConsoleKeys(cfg),
		CreditsBudget:   1_000_000,
		UpstreamRouter:  buildProviderRouter(cfg, logger),
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

// buildConsoleKeys renders privacy-safe API-key metadata for the console from the
// same ECHELON_API_KEYS env ("key:tenant:keyid:plan,..."). Only the last 4 chars
// of each key are retained.
func buildConsoleKeys(cfg config.Config) []gateway.ConsoleKeyInfo {
	raw := strings.TrimSpace(os.Getenv("ECHELON_API_KEYS"))
	if raw == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var keys []gateway.ConsoleKeyInfo
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		key := parts[0]
		last4 := key
		if len(key) > 4 {
			last4 = key[len(key)-4:]
		}
		id := parts[1]
		if len(parts) > 2 {
			id = parts[2]
		}
		keys = append(keys, gateway.ConsoleKeyInfo{
			ID: id, Label: parts[1], Last4: last4, CreatedAt: now, Status: "active",
			RateLimitRpm: int(cfg.RateLimit.Limit), CreditBudget: 100_000,
		})
	}
	return keys
}

// buildCreditSeed parses ECHELON_API_KEYS ("key:tenant:keyid:plan,...") the same
// way buildConsoleKeys/buildAuthenticator do (parts[1] is the tenant, matching the
// core.Identity.TenantID the authenticator emits) and returns each distinct tenant
// seeded to 100_000 credits — the same budget buildConsoleKeys surfaces to the
// console. Returns an empty map when auth is disabled (no tenant to bill).
func buildCreditSeed(cfg config.Config) map[string]int64 {
	_ = cfg // seeding derives from ECHELON_API_KEYS, kept for signature symmetry
	seed := map[string]int64{}
	raw := strings.TrimSpace(os.Getenv("ECHELON_API_KEYS"))
	if raw == "" {
		return seed
	}
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		tenant := parts[1]
		if tenant == "" {
			continue
		}
		seed[tenant] = 100_000
	}
	return seed
}

// buildAuthenticator reads ECHELON_API_KEYS ("key:tenant:keyid:plan,...") and
// returns nil (auth disabled) when unset, keeping local development frictionless.
func buildAuthenticator(logger *slog.Logger) ports.Authenticator {
	raw := strings.TrimSpace(os.Getenv("ECHELON_API_KEYS"))
	if raw == "" {
		logger.Info("api-key auth disabled (no ECHELON_API_KEYS)")
		return nil
	}
	keys := map[string]core.Identity{}
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		id := core.Identity{TenantID: parts[1]}
		if len(parts) > 2 {
			id.APIKeyID = parts[2]
		}
		if len(parts) > 3 {
			id.Plan = parts[3]
		}
		keys[parts[0]] = id
	}
	if len(keys) == 0 {
		return nil
	}
	authenticator, err := auth.NewStaticAPIKeyAuthenticator(keys)
	if err != nil {
		logger.Error("api-key auth build failed; auth disabled", "error", err)
		return nil
	}
	logger.Info("api-key auth enabled", "key_count", len(keys))
	return authenticator
}
