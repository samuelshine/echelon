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
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/guard"
	"github.com/jscyril/echelon/internal/ingress"
	"github.com/jscyril/echelon/internal/ports"
	"github.com/jscyril/echelon/internal/ratelimit"
	"github.com/jscyril/echelon/internal/telemetry"
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
	authenticator := buildAuthenticator(logger)
	var rateLimiter ports.RateLimiter
	if cfg.RateLimit.Backend == "memory" {
		rateLimiter = ratelimit.NewMemoryTokenBucket()
	}

	telemetryStore := telemetry.NewStore(5000)

	app := gateway.New(gateway.Options{
		Config:        cfg,
		Logger:        logger,
		Guards:        filterChain,
		OutputScanner: outputScanner,
		Ingress:       ingressCascade,
		Authenticator: authenticator,
		RateLimiter:   rateLimiter,
		Telemetry:     telemetryStore,
		ConsoleKeys:   buildConsoleKeys(cfg),
		CreditsBudget: 1_000_000,
		HTTPClient: &http.Client{
			Timeout: cfg.UpstreamTimeout,
		},
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
