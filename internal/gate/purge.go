package gate

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/store"
)

// PurgeInterval is how often expired rows are removed. It is also the window
// the nonce table cap is re-measured on.
const PurgeInterval = time.Minute

// PurgeGrace is how long an expired nonce or idle session is kept past its
// expiry. A row deleted while a request is still racing its own
// `delete ... returning` would make the request fail as a replay; the grace
// removes that race without keeping an expired row usable, because the verify
// statement's own predicate already refuses it.
const PurgeGrace = time.Hour

// purgeLoud is the row count above which a purge is reported at info. A purge
// that removes hundreds of thousands of rows is a symptom — a dead ticker, a
// clock jump — not a routine success, and an operator should see it without
// turning on debug logging.
const purgeLoud = 10000

// PurgeCounts is what one purge removed.
type PurgeCounts struct {
	Nonces   int64
	Sessions int64
}

// Purge removes expired nonces and sessions in one transaction. Both
// statements commit or neither does: a failure of the second must not leave the
// first applied and the log line claiming both counts.
//
// It is safe to call from more than one goroutine. The statements are
// idempotent deletes with their own predicates, so a concurrent pass removes
// rows the other has not, and both report what they themselves removed.
func (g *Gate) Purge(ctx context.Context) (PurgeCounts, error) {
	var counts PurgeCounts

	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return counts, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := purgeOne(ctx, tx, store.StmtPurge, &counts.Nonces); err != nil {
		return PurgeCounts{}, err
	}
	if err := purgeOne(ctx, tx, store.StmtPurgeSessions, &counts.Sessions); err != nil {
		return PurgeCounts{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PurgeCounts{}, err
	}

	g.logPurge(counts)
	return counts, nil
}

func purgeOne(ctx context.Context, tx pgx.Tx, statement string, into *int64) error {
	tag, err := tx.Exec(ctx, statement)
	if err != nil {
		return err
	}
	*into = tag.RowsAffected()
	return nil
}

// logPurge records what the pass removed. The counts are not secrets; the row
// contents never reach the log.
func (g *Gate) logPurge(c PurgeCounts) {
	if c.Nonces > purgeLoud || c.Sessions > purgeLoud {
		g.log.Info("purge removed an unusual number of rows",
			"nonces", c.Nonces, "sessions", c.Sessions)
		return
	}
	g.log.Debug("purge", "nonces", c.Nonces, "sessions", c.Sessions)
}

// RunMaintenance drives the purge from one ticker for the life of the process.
// The first pass is run synchronously by the caller before the listener opens,
// so a restarted gate cleans up before it decides a request; this loop only
// repeats it.
//
// A failed pass is logged and the loop continues: a database outage should not
// stop the gate from trying again, and the nonce cap is the backstop that keeps
// the table bounded while the ticker is failing.
func (g *Gate) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(PurgeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := g.Purge(ctx); err != nil {
				g.log.Warn("purge failed", "error", audit.Error(err))
			}
			// The nonce cap is measured on the same schedule, and the handler
			// reads the cached answer rather than counting per request.
			g.refreshCap(ctx)
		}
	}
}
