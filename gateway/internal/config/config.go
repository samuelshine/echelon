package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddress         = ":8080"
	defaultUpstreamBaseURL = "https://api.openai.com"
	defaultMaxRequestBytes = 1_048_576
	defaultRequestTimeout  = 30 * time.Second
	defaultUpstreamTimeout = 20 * time.Second
)

type PipelineConfig struct {
	HeuristicTimeout   time.Duration
	MLTimeout          time.Duration
	JudgeTimeout       time.Duration
	EgressTimeout      time.Duration
	MLBaseURL          *url.URL
	JudgeBaseURL       *url.URL
	EgressMLBaseURL    *url.URL
	EgressJudgeBaseURL *url.URL
	MLBlockThreshold   float64
	MLJudgeThreshold   float64
	FailClosed         bool
}

type RateLimitConfig struct {
	Backend   string
	RedisURL  string
	Limit     int64
	Burst     int64
	Window    time.Duration
	KeyPrefix string
}

type ProviderConfig struct {
	BaseURL string
	APIKey  string
}

type ProvidersConfig struct {
	OpenAI    ProviderConfig
	Gemini    ProviderConfig
	Anthropic ProviderConfig
	Ollama    ProviderConfig

	ModelRoutes     string
	DefaultProvider string
}

type Config struct {
	Address         string
	UpstreamBaseURL *url.URL
	UpstreamAPIKey  string
	MaxRequestBytes int64
	UpstreamTimeout time.Duration
	SystemCanary    string
	LogLevel        slog.Level
	RequestTimeout  time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Pipeline        PipelineConfig
	RateLimit       RateLimitConfig
	Providers       ProvidersConfig
	// StreamFastMode opts into genuine incremental (low-latency) streaming for
	// clients that request stream:true. Off by default: the default buffered mode
	// fully egress-scans a response before delivering it. Fast mode is a real,
	// documented tradeoff — PII/policy are still enforced at chunk granularity
	// (one-chunk lag), but ML/judge egress detection becomes post-hoc (it can flag
	// and log an already-delivered response but cannot block it). See README.
	StreamFastMode bool
	// AuditDatabaseURL, when set, enables the durable Postgres audit sink for the
	// telemetry ring buffer. Unset (the default) keeps the gateway purely
	// in-memory with no Postgres dependency.
	AuditDatabaseURL string
}

func Load() (Config, error) {
	upstream, err := url.Parse(envString("UPSTREAM_BASE_URL", defaultUpstreamBaseURL))
	if err != nil {
		return Config{}, fmt.Errorf("parse UPSTREAM_BASE_URL: %w", err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return Config{}, fmt.Errorf("UPSTREAM_BASE_URL must include scheme and host")
	}

	maxRequestBytes, err := envInt64("MAX_REQUEST_BYTES", defaultMaxRequestBytes)
	if err != nil {
		return Config{}, err
	}

	upstreamTimeout, err := envDuration("UPSTREAM_TIMEOUT", defaultUpstreamTimeout)
	if err != nil {
		return Config{}, err
	}

	logLevel, err := parseLogLevel(envString("LOG_LEVEL", "info"))
	if err != nil {
		return Config{}, err
	}

	requestTimeout, err := envDuration("REQUEST_TIMEOUT", defaultRequestTimeout)
	if err != nil {
		return Config{}, err
	}

	pipeline, err := loadPipelineConfig()
	if err != nil {
		return Config{}, err
	}

	rateLimit, err := loadRateLimitConfig()
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Address:          envString("HTTP_ADDR", defaultAddress),
		UpstreamBaseURL:  upstream,
		UpstreamAPIKey:   os.Getenv("UPSTREAM_API_KEY"),
		MaxRequestBytes:  maxRequestBytes,
		UpstreamTimeout:  upstreamTimeout,
		SystemCanary:     envString("SYSTEM_CANARY", "[SYSTEM_CANARY_DEV]"),
		LogLevel:         logLevel,
		RequestTimeout:   requestTimeout,
		Pipeline:         pipeline,
		RateLimit:        rateLimit,
		Providers:        loadProvidersConfig(),
		AuditDatabaseURL: strings.TrimSpace(os.Getenv("AUDIT_DATABASE_URL")),
	}
	if cfg.StreamFastMode, err = envBool("STREAM_FAST_MODE", false); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = envDuration("HTTP_READ_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.WriteTimeout, err = envDuration("HTTP_WRITE_TIMEOUT", 35*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.IdleTimeout, err = envDuration("HTTP_IDLE_TIMEOUT", 90*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = envDuration("SHUTDOWN_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadPipelineConfig() (PipelineConfig, error) {
	cfg := PipelineConfig{}
	var err error
	if cfg.FailClosed, err = envBool("SECURITY_FAIL_CLOSED", true); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.HeuristicTimeout, err = envDuration("HEURISTIC_TIMEOUT", 5*time.Millisecond); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.MLTimeout, err = envDuration("ML_TIMEOUT", 150*time.Millisecond); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.JudgeTimeout, err = envDuration("JUDGE_TIMEOUT", 800*time.Millisecond); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.EgressTimeout, err = envDuration("EGRESS_TIMEOUT", 250*time.Millisecond); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.MLBaseURL, err = optionalURL("ML_BASE_URL"); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.JudgeBaseURL, err = optionalURL("JUDGE_BASE_URL"); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.EgressMLBaseURL, err = optionalURL("EGRESS_ML_BASE_URL"); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.EgressJudgeBaseURL, err = optionalURL("EGRESS_JUDGE_BASE_URL"); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.MLBlockThreshold, err = envProbability("ML_BLOCK_THRESHOLD", 0.90); err != nil {
		return PipelineConfig{}, err
	}
	if cfg.MLJudgeThreshold, err = envProbability("ML_JUDGE_THRESHOLD", 0.55); err != nil {
		return PipelineConfig{}, err
	}
	return cfg, nil
}

func loadRateLimitConfig() (RateLimitConfig, error) {
	cfg := RateLimitConfig{
		Backend:   strings.ToLower(envString("RATE_LIMIT_BACKEND", "memory")),
		RedisURL:  strings.TrimSpace(os.Getenv("REDIS_URL")),
		KeyPrefix: envString("RATE_LIMIT_KEY_PREFIX", "echelon:rl:"),
	}
	var err error
	if cfg.Limit, err = envInt64("RATE_LIMIT_REQUESTS", 120); err != nil {
		return RateLimitConfig{}, err
	}
	if cfg.Burst, err = envInt64("RATE_LIMIT_BURST", 20); err != nil {
		return RateLimitConfig{}, err
	}
	if cfg.Window, err = envDuration("RATE_LIMIT_WINDOW", time.Minute); err != nil {
		return RateLimitConfig{}, err
	}
	return cfg, nil
}

func loadProvidersConfig() ProvidersConfig {
	// For backward compatibility, default OpenAI to the legacy UPSTREAM_BASE_URL.
	openAIBase := envString("PROVIDER_OPENAI_BASE_URL", envString("UPSTREAM_BASE_URL", defaultUpstreamBaseURL))
	openAIKey := envString("PROVIDER_OPENAI_API_KEY", os.Getenv("UPSTREAM_API_KEY"))

	return ProvidersConfig{
		OpenAI: ProviderConfig{
			BaseURL: openAIBase,
			APIKey:  openAIKey,
		},
		Gemini: ProviderConfig{
			BaseURL: os.Getenv("PROVIDER_GEMINI_BASE_URL"),
			APIKey:  os.Getenv("PROVIDER_GEMINI_API_KEY"),
		},
		Anthropic: ProviderConfig{
			BaseURL: os.Getenv("PROVIDER_ANTHROPIC_BASE_URL"),
			APIKey:  os.Getenv("PROVIDER_ANTHROPIC_API_KEY"),
		},
		Ollama: ProviderConfig{
			BaseURL: os.Getenv("PROVIDER_OLLAMA_BASE_URL"),
			APIKey:  os.Getenv("PROVIDER_OLLAMA_API_KEY"),
		},
		ModelRoutes:     os.Getenv("MODEL_ROUTES"),
		DefaultProvider: envString("DEFAULT_PROVIDER", "openai"),
	}
}

func (c Config) Validate() error {
	if c.UpstreamBaseURL == nil || c.UpstreamBaseURL.Scheme == "" || c.UpstreamBaseURL.Host == "" {
		return fmt.Errorf("UPSTREAM_BASE_URL must include scheme and host")
	}
	if c.Pipeline.MLJudgeThreshold > c.Pipeline.MLBlockThreshold {
		return fmt.Errorf("ML_JUDGE_THRESHOLD must not exceed ML_BLOCK_THRESHOLD")
	}
	if c.RateLimit.Backend != "memory" && c.RateLimit.Backend != "redis" {
		return fmt.Errorf("RATE_LIMIT_BACKEND must be memory or redis")
	}
	if c.RateLimit.Backend == "redis" && c.RateLimit.RedisURL == "" {
		return fmt.Errorf("REDIS_URL is required when RATE_LIMIT_BACKEND=redis")
	}
	minimumBudget := c.Pipeline.HeuristicTimeout + c.Pipeline.MLTimeout +
		c.Pipeline.JudgeTimeout + c.UpstreamTimeout + c.Pipeline.EgressTimeout
	if minimumBudget > c.RequestTimeout {
		return fmt.Errorf("REQUEST_TIMEOUT must cover ingress, upstream, and egress budgets (%s)", minimumBudget)
	}
	return nil
}

func envString(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt64(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return value, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return value, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return value, nil
}

func envProbability(key string, fallback float64) (float64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value < 0 || value > 1 {
		return 0, fmt.Errorf("%s must be between 0 and 1", key)
	}
	return value, nil
}

func optionalURL(key string) (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%s must include scheme and host", key)
	}
	return parsed, nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, error")
	}
}
