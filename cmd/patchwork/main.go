package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tionis/patchwork/internal/auth"
	"github.com/tionis/patchwork/internal/config"
	"github.com/tionis/patchwork/internal/docruntime"
	"github.com/tionis/patchwork/internal/httpserver"
	"github.com/tionis/patchwork/internal/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevelFromEnv()}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := migrations.BootstrapService(ctx, cfg.DataDir, cfg.DocumentsDir, cfg.ServiceDBPath); err != nil {
		logger.Error("failed to bootstrap service", "error", err)
		os.Exit(1)
	}

	runtimes := docruntime.NewManager(cfg, logger)
	defer runtimes.Close()
	go runtimes.StartCleanupLoop(ctx)

	authSvc, err := auth.NewService(cfg.ServiceDBPath, cfg.BootstrapAdminToken, logger)
	if err != nil {
		logger.Error("failed to initialize auth service", "error", err)
		os.Exit(1)
	}
	defer authSvc.Close()

	api := httpserver.New(cfg, logger, runtimes, authSvc)
	httpSrv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("patchwork server starting", "addr", cfg.BindAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("http server error", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown failed", "error", err)
	}

	if err := api.Shutdown(shutdownCtx); err != nil {
		logger.Error("api shutdown failed", "error", err)
	}

	logger.Info("patchwork server stopped")
}

func logLevelFromEnv() slog.Level {
	switch os.Getenv("PATCHWORK_LOG_LEVEL") {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
