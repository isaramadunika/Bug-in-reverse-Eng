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

	"github.com/tetraneurons/reversebug/api/internal/audit"
	"github.com/tetraneurons/reversebug/api/internal/config"
	"github.com/tetraneurons/reversebug/api/internal/db"
	"github.com/tetraneurons/reversebug/api/internal/mail"
	"github.com/tetraneurons/reversebug/api/internal/ratelimit"
	"github.com/tetraneurons/reversebug/api/internal/server"
	"github.com/tetraneurons/reversebug/api/internal/store"
)

func main() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	if err := run(); err != nil {
		slog.Error("server startup error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	slog.Info("connecting to database", "url", redactURL(cfg.DatabaseURL))
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database connect: %w", err)
	}
	defer pool.Close()

	slog.Info("running database migrations")
	if err := db.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	// Initialize ratelimiter (Redis if configured, otherwise Memory in dev)
	var limiter ratelimit.Limiter
	if cfg.RedisURL != "" {
		slog.Info("connecting to redis for rate limiting")
		rLimiter, err := ratelimit.NewRedis(cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("redis connect: %w", err)
		}
		limiter = rLimiter
	} else {
		slog.Warn("using in-memory rate limiter (set RB_REDIS_URL for production clustering)")
		limiter = ratelimit.NewMemory()
	}

	// Mailer
	var mailer mail.Mailer
	if cfg.SMTPHost != "" {
		mailer = &mail.SMTP{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			User:     cfg.SMTPUser,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		}
	} else {
		slog.Warn("using recorder mailer (no SMTP configured)")
		mailer = &mail.Recorder{}
	}

	st := store.New(pool)
	auditLogger := audit.New(pool)

	srv, err := server.New(server.Deps{
		Config:  cfg,
		Store:   st,
		Audit:   auditLogger,
		Mailer:  mailer,
		Limiter: limiter,
	})
	if err != nil {
		return fmt.Errorf("initialize server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	shutdownDone := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig

		slog.Info("shutting down HTTP server gracefully...")
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("http shutdown error", "err", err)
		}
		close(shutdownDone)
	}()

	slog.Info("ReverseBug API listening", "addr", cfg.HTTPAddr, "env", cfg.Env)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and serve: %w", err)
	}

	<-shutdownDone
	slog.Info("ReverseBug API terminated cleanly")
	return nil
}

func redactURL(u string) string {
	if len(u) > 10 {
		return u[:10] + "..."
	}
	return u
}
