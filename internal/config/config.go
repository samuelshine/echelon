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
	defaultUpstreamTimeout = 60 * time.Second
)

type Config struct {
	Address         string
	UpstreamBaseURL *url.URL
	UpstreamAPIKey  string
	MaxRequestBytes int64
	UpstreamTimeout time.Duration
	SystemCanary    string
	LogLevel        slog.Level
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

	return Config{
		Address:         envString("HTTP_ADDR", defaultAddress),
		UpstreamBaseURL: upstream,
		UpstreamAPIKey:  os.Getenv("UPSTREAM_API_KEY"),
		MaxRequestBytes: maxRequestBytes,
		UpstreamTimeout: upstreamTimeout,
		SystemCanary:    envString("SYSTEM_CANARY", "[SYSTEM_CANARY_DEV]"),
		LogLevel:        logLevel,
	}, nil
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
