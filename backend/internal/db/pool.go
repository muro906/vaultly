// Package db owns the PostgreSQL connection pool, the embedded migrations and
// the generated type-safe query layer.
package db

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations exposes the embedded migration files so they travel with the
// binary. A deployment therefore never needs the source tree to migrate.
func Migrations() embed.FS { return migrationsFS }

// PoolConfig tunes the connection pool. The zero value is not useful; use
// DefaultPoolConfig.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

// DefaultPoolConfig returns settings suited to an API server that fans work out
// across goroutines: enough connections to keep the decrypt worker pool busy,
// with a few kept warm so a burst does not pay connection setup.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:          16,
		MinConns:          2,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		ConnectTimeout:    10 * time.Second,
	}
}

// NewPool opens a connection pool and verifies it can reach the database.
// Returning only after a successful ping means a server that starts up has
// already proven its database configuration.
func NewPool(ctx context.Context, databaseURL string, cfg PoolConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: parse database url: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.HealthCheckPeriod = cfg.HealthCheckPeriod
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return pool, nil
}

// WaitForPool retries NewPool until it succeeds or the deadline passes. It
// exists for container startup, where the database may still be accepting
// connections a moment after it reports healthy.
func WaitForPool(ctx context.Context, databaseURL string, cfg PoolConfig, timeout time.Duration) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(timeout)
	backoff := 250 * time.Millisecond

	var lastErr error
	for {
		pool, err := NewPool(ctx, databaseURL, cfg)
		if err == nil {
			return pool, nil
		}
		lastErr = err

		if time.Now().Add(backoff).After(deadline) {
			return nil, fmt.Errorf("db: database unreachable after %s: %w", timeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}
