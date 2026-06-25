package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/guard"
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

	app := gateway.New(gateway.Options{
		Config:        cfg,
		Logger:        logger,
		Guards:        filterChain,
		OutputScanner: outputScanner,
		HTTPClient: &http.Client{
			Timeout: cfg.UpstreamTimeout,
		},
	})

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}
