package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	clearConfigEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("RequestTimeout = %s", cfg.RequestTimeout)
	}
	if cfg.Pipeline.MLJudgeThreshold != 0.55 {
		t.Fatalf("MLJudgeThreshold = %f", cfg.Pipeline.MLJudgeThreshold)
	}
	if cfg.RateLimit.Backend != "memory" {
		t.Fatalf("RateLimit.Backend = %q", cfg.RateLimit.Backend)
	}
}

func TestLoadRejectsInvertedClassifierThresholds(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("ML_JUDGE_THRESHOLD", "0.95")
	t.Setenv("ML_BLOCK_THRESHOLD", "0.80")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ML_JUDGE_THRESHOLD") {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

func TestLoadRequiresRedisURL(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("RATE_LIMIT_BACKEND", "redis")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "REDIS_URL") {
		t.Fatalf("expected Redis URL error, got %v", err)
	}
}

func TestLoadRejectsInsufficientGlobalBudget(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("REQUEST_TIMEOUT", "1s")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "REQUEST_TIMEOUT") {
		t.Fatalf("expected budget error, got %v", err)
	}
}

func TestLoadRejectsInvalidFailPolicy(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("SECURITY_FAIL_CLOSED", "sometimes")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SECURITY_FAIL_CLOSED") {
		t.Fatalf("expected fail-policy error, got %v", err)
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	keys := []string{
		"UPSTREAM_BASE_URL", "UPSTREAM_API_KEY", "MAX_REQUEST_BYTES", "UPSTREAM_TIMEOUT",
		"LOG_LEVEL", "REQUEST_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT",
		"HTTP_IDLE_TIMEOUT", "SHUTDOWN_TIMEOUT", "HEURISTIC_TIMEOUT", "ML_TIMEOUT",
		"JUDGE_TIMEOUT", "EGRESS_TIMEOUT", "ML_BASE_URL", "JUDGE_BASE_URL",
		"ML_BLOCK_THRESHOLD", "ML_JUDGE_THRESHOLD", "SECURITY_FAIL_CLOSED",
		"RATE_LIMIT_BACKEND", "REDIS_URL", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_BURST",
		"RATE_LIMIT_WINDOW", "RATE_LIMIT_KEY_PREFIX",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}
