package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/config"
)

// TestBuildConsoleAuthFailsClosed is the policy half of the console-auth fix.
// The middleware only enforces when an authenticator is present, so the
// guarantee that production never runs without one lives here: an unset
// CONSOLE_TOKEN must be a startup error, not a permissive default.
func TestBuildConsoleAuthFailsClosed(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	got, err := buildConsoleAuth(config.Config{}, logger)
	if err == nil {
		t.Fatalf("unset CONSOLE_TOKEN: expected a startup error, got authenticator %v", got)
	}
	if !strings.Contains(err.Error(), "CONSOLE_TOKEN") {
		t.Errorf("error should name the variable to set, got: %v", err)
	}
}

func TestBuildConsoleAuthWithToken(t *testing.T) {
	cfg := config.Config{ConsoleAuth: config.ConsoleAuthConfig{Token: "op-secret"}}
	got, err := buildConsoleAuth(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected an authenticator")
	}
	if !got.VerifyConsoleToken("Bearer op-secret") {
		t.Error("configured token should verify")
	}
	if got.VerifyConsoleToken("Bearer wrong") {
		t.Error("wrong token must not verify")
	}
}

// TestBuildConsoleAuthDisabledIsLoud allows the opt-out but requires it to
// announce itself, so an unauthenticated console cannot be inherited silently
// from a stale environment.
func TestBuildConsoleAuthDisabledIsLoud(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := config.Config{ConsoleAuth: config.ConsoleAuthConfig{Disabled: true}}
	got, err := buildConsoleAuth(cfg, logger)
	if err != nil {
		t.Fatalf("explicit opt-out should not error: %v", err)
	}
	if got != nil {
		t.Fatal("opt-out should yield no authenticator")
	}
	if !strings.Contains(logged.String(), "UNAUTHENTICATED") {
		t.Errorf("opt-out must warn loudly, got: %s", logged.String())
	}
}
