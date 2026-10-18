// Package db provides the PostgreSQL pool and the embedded migration runner.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/tetraneurons/reversebug/api/migrations"
)

func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations. It is idempotent and safe to run
// concurrently: goose takes a session-level advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	return migrateDB(ctx, sqlDB)
}

func migrateDB(ctx context.Context, sqlDB *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS,
		goose.WithSessionLocker(mustLocker()))
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}
