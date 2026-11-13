package store

import (
	"context"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Counter counts statements the service issues through the pool. It exists so
// the one-round-trip budget can be asserted rather than assumed: the tests read
// it, and the benchmark reports from it.
//
// It counts Query, QueryRow and Exec calls, which pgx funnels through the same
// tracer. Pool setup, Prepare and transaction control are not statements in
// this sense and are not counted.
type Counter struct{ n atomic.Int64 }

// Add is used by the tracer.
func (c *Counter) Add(delta int64) {
	if c != nil {
		c.n.Add(delta)
	}
}

// Value returns the statements counted so far.
func (c *Counter) Value() int64 {
	if c == nil {
		return 0
	}
	return c.n.Load()
}

// Reset zeroes the counter, for tests that measure one request.
func (c *Counter) Reset() {
	if c != nil {
		c.n.Store(0)
	}
}

// queryTracer implements pgx.QueryTracer.
type queryTracer struct{ counter *Counter }

func (t queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	t.counter.Add(1)
	return ctx
}

func (queryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Statement is one named prepared statement. Preparing at connection time
// removes the Describe round trip a query pays the first time it runs, which is
// the difference between a warm pool and a warm pool that still parses.
type Statement struct {
	Name string
	SQL  string
}

// Option adjusts a pool before it is created.
type Option func(*pgxpool.Config)

// WithQueryCounter attaches c to the pool. A nil counter is ignored, so a
// caller that does not measure does not pay.
func WithQueryCounter(c *Counter) Option {
	return func(cfg *pgxpool.Config) {
		if c == nil {
			return
		}
		cfg.ConnConfig.Tracer = queryTracer{counter: c}
	}
}

// WithStatements prepares each named statement on every connection as it
// opens. Statements are then executed by name, so no request pays to parse
// SQL.
func WithStatements(stmts ...Statement) Option {
	return func(cfg *pgxpool.Config) {
		if len(stmts) == 0 {
			return
		}
		list := append([]Statement(nil), stmts...)
		previous := cfg.AfterConnect
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if previous != nil {
				if err := previous(ctx, conn); err != nil {
					return err
				}
			}
			for _, s := range list {
				if _, err := conn.Prepare(ctx, s.Name, s.SQL); err != nil {
					return err
				}
			}
			return nil
		}
	}
}
