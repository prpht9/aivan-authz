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

// Pool sizing. The decision is one statement of a few hundred microseconds, so
// a 200 rps arrival has well under one request in flight on average. Sixteen
// connections is many times what that needs and still far below the database's
// connection limit. Two are the floor pgxpool keeps open; startup warms all of
// them (Warm), so no request pays a dial.
const (
	maxConns int32 = 16
	minConns int32 = 2
)

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
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
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

// Warm establishes n connections before the listener opens.
//
// pgxpool creates connections lazily: MinConns are opened in the background and
// the first requests race them. A request that arrives while its connection is
// still being dialled is a connection-pool wait, which is exactly the event
// Phase G's load acceptance says must be zero. Warming removes it from the
// request path and puts it in startup, where a slow database is a start failure
// rather than a slow user.
//
// The connections are acquired and released immediately, so the pool keeps them
// as idle connections up to MaxConns.
func Warm(ctx context.Context, pool *pgxpool.Pool, n int32) error {
	if pool == nil || n <= 0 {
		return nil
	}
	conns := make([]*pgxpool.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Release()
		}
	}()
	for i := int32(0); i < n; i++ {
		c, err := pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("warm the connection pool: %w", err)
		}
		conns = append(conns, c)
	}
	return nil
}

// WarmCount is how many connections startup should hold: the whole pool. The
// gate opens at most MaxConns anyway, so this is not extra connections — it is
// the same set, opened before the first request rather than during it.
func WarmCount() int32 { return maxConns }
