// Package store owns the database connection and the migrations that create
// the gate's schema.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectTimeout bounds pool creation so a bad DSN or an unreachable database
// fails the start rather than hanging it.
const ConnectTimeout = 5 * time.Second

// DB is the gate's database handle. One pool, shared by every request.
type DB struct {
	Pool *pgxpool.Pool
}

// Open connects the pool and proves the database answers. Options adjust the
// pool before it is created; the instrumentation in instrument.go uses them.
func Open(ctx context.Context, dsn string, opts ...Option) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "aivan-authz"
	cfg.MaxConns = 16
	cfg.MinConns = 2
	for _, opt := range opts {
		opt(cfg)
	}

	ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unreachable: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases every connection.
func (d *DB) Close() {
	if d != nil && d.Pool != nil {
		d.Pool.Close()
	}
}
