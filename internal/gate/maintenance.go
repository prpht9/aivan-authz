package gate

import (
	"context"
	"sync"
	"time"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/store"
)

// CapInterval is how often the nonce table is counted. It is the interval the
// purge used to run on; the count is now the gate's only scheduled work,
// because removing expired rows is administration and belongs to the admin
// binary (doc/schema-handover.md §5).
//
// The count is what bounds the table: a fresh count every minute is what turns
// an unbounded insert path into a refusal once the table is full, even when
// nobody is running the purge CronJob.
const CapInterval = time.Minute

// maintainer holds the answer to "is the nonce table at its cap". The count is
// cached, so the nonce handler reads a value instead of counting per request.
type maintainer struct {
	mu      sync.Mutex
	lastRun time.Time
	full    bool
	now     func() time.Time
}

// maintain measures the nonce table if the interval has elapsed and reports
// whether the table is at the cap.
//
// The handler calls it before every insert so the cap holds even when no ticker
// is running, which is how the tests build a gate. RunMaintenance drives the
// same function, and the two cannot disagree because the schedule is the shared
// state.
func (g *Gate) maintain(ctx context.Context) (bool, error) {
	m := &g.maint

	m.mu.Lock()
	now := m.now()
	if !m.lastRun.IsZero() && now.Sub(m.lastRun) < CapInterval {
		full := m.full
		m.mu.Unlock()
		return full, nil
	}
	m.lastRun = now
	m.mu.Unlock()

	return g.refreshCap(ctx)
}

// MeasureNonceCap counts the nonce table once and caches the answer. Startup
// calls it so the first nonce request does not pay the count, and the ticker
// repeats it on CapInterval.
func (g *Gate) MeasureNonceCap(ctx context.Context) (bool, error) {
	return g.refreshCap(ctx)
}

// refreshCap counts the nonce table and caches whether it is at the cap. A
// failed count leaves the last measurement in place rather than reporting the
// table empty, so a database outage cannot be mistaken for a free table.
func (g *Gate) refreshCap(ctx context.Context) (bool, error) {
	var count int64
	if err := g.pool.QueryRow(ctx, store.StmtCountID).Scan(&count); err != nil {
		return false, err
	}
	full := count >= NonceTableCap

	m := &g.maint
	m.mu.Lock()
	m.full = full
	m.mu.Unlock()
	return full, nil
}

// RunMaintenance measures the nonce table for the life of the process. The
// first measurement is made by the handler before its first insert, so this
// loop only repeats it.
//
// It no longer purges. The gate holds no DELETE on authz.nonces or
// authz.sessions; `authz-admin purge` removes expired rows as a CronJob, which
// keeps "the gate cannot change what already exists" true for the scratch
// tables as well as the durable ones.
func (g *Gate) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(CapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := g.refreshCap(ctx); err != nil {
				g.log.Warn("nonce cap measurement failed", "error", audit.Error(err))
			}
		}
	}
}
