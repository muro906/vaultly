// Command api runs the Vaultly HTTP server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vaultly/backend/internal/auth"
	"vaultly/backend/internal/config"
	"vaultly/backend/internal/db"
	vaultlyhttp "vaultly/backend/internal/http"
	"vaultly/backend/internal/ratelimit"
	"vaultly/backend/internal/service"
)

// shutdownTimeout bounds how long a graceful stop waits for in-flight
// requests before the process exits anyway.
const shutdownTimeout = 20 * time.Second

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local server and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vaultly: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	// Signals are wired up before anything is opened, so a stop request during
	// slow startup is honoured rather than ignored.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	keyring, err := cfg.Keyring()
	if err != nil {
		return fmt.Errorf("build keyring: %w", err)
	}

	logger.Info("connecting to the database")
	pool, err := db.WaitForPool(ctx, cfg.DatabaseURL, db.DefaultPoolConfig(), 30*time.Second)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Migrating on start keeps a container deployment to a single step. It is
	// idempotent, so replicas racing each other is harmless.
	logger.Info("applying database migrations")
	if err := db.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}
	version, dirty, err := db.MigrationVersion(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	if dirty {
		// A dirty schema means a migration failed partway. Serving against it
		// would be guessing at what the schema actually is.
		return fmt.Errorf("database schema is dirty at version %d; resolve it manually before starting", version)
	}
	logger.Info("database ready", slog.Uint64("schema_version", uint64(version)))

	store := service.NewStore(pool)
	authz := service.NewAuthorizer(store)

	audit := service.NewAuditRecorder(store, logger, service.AuditConfig{})
	// Closed before the pool so that queued events still have a database to
	// be written to.
	defer audit.Close()

	limiter := ratelimit.New(ratelimit.Config{})
	defer limiter.Close()

	issuer := auth.NewTokenIssuer(cfg.JWTSecret, cfg.AccessTokenTTL)

	secrets := service.NewSecretService(store, authz, keyring, audit)
	projects := service.NewProjectService(store, authz, audit)

	router := vaultlyhttp.NewRouter(vaultlyhttp.RouterDeps{
		Config: cfg,
		Services: vaultlyhttp.Services{
			Auth:       service.NewAuthService(store, issuer, audit, logger, cfg.RefreshTokenTTL),
			Workspaces: service.NewWorkspaceService(store, authz, audit),
			Projects:   projects,
			Secrets:    secrets,
			Promotion:  service.NewPromotionService(store, authz, secrets, projects, keyring, audit),
			Tokens:     service.NewTokenService(store, authz, secrets, projects, audit),
			Audit:      service.NewAuditService(store, authz),
		},
		Issuer:  issuer,
		Limiter: limiter,
		Pool:    pool,
		Logger:  logger,
	})

	server := &http.Server{
		Addr:    cfg.Addr(),
		Handler: router,
		// A slow or absent client must not be able to hold a connection open
		// indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server listening",
			slog.String("addr", server.Addr),
			slog.String("environment", string(cfg.Environment)))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server failed: %w", err)

	case <-ctx.Done():
		logger.Info("shutdown requested, draining connections")

		// A fresh context: the one that was cancelled by the signal cannot
		// also govern how long the drain is allowed to take.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		// Flushing here, while the pool is still open, is what makes the
		// audit log complete across a restart.
		logger.Info("flushing audit log")
		audit.Close()

		logger.Info("shutdown complete")
		return nil
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}

	// JSON in production so logs are machine-parseable; plain text locally so
	// they are readable in a terminal.
	if cfg.Environment.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// runHealthcheck probes the local server. It exists so the container image
// needs no curl or wget for its healthcheck.
func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
