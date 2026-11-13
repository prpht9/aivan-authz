// Package httpx carries the gate's own HTTP surface: the health endpoints and
// the router they live on. Nothing here authenticates anything.
package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ReadinessTimeout bounds /readyz. A gate that cannot read its own tables
// within this must leave rotation, so the bound is tighter than any client's
// patience.
const ReadinessTimeout = 500 * time.Millisecond

// Health serves the two probes.
type Health struct {
	Pool *pgxpool.Pool
	Log  *slog.Logger
}

// Liveness always succeeds: it touches nothing, so a database outage cannot
// trigger a restart loop.
func (h *Health) Liveness(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusOK, "ok\n")
}

// Readiness proves the database answers and that the gate can read the table
// its hot path needs. Both must succeed within ReadinessTimeout. A gate that
// cannot read authz.devices must leave rotation (spec §8.4).
func (h *Health) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ReadinessTimeout)
	defer cancel()

	if err := checkReady(ctx, h.Pool); err != nil {
		reason := readyReason(err)
		h.Log.Warn("not ready", "reason", reason, "request_id", RequestIDFrom(r.Context()))
		writeText(w, http.StatusServiceUnavailable, reason+"\n")
		return
	}
	writeText(w, http.StatusOK, "ok\n")
}

// checkReady runs the two statements the design requires and reports which one
// failed. Errors are mapped to fixed reasons so the endpoint never leaks a DSN
// or a schema name.
func checkReady(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errDatabaseUnreachable
	}

	var one int
	if err := pool.QueryRow(ctx, `select 1`).Scan(&one); err != nil {
		return classify(err, errDatabaseTimeout, errDatabaseUnreachable)
	}

	// An empty authz.devices returns no rows, which is still a successful read:
	// only an error means the gate cannot read the table it depends on.
	var probe int
	err := pool.QueryRow(ctx, `select 1 from authz.devices limit 1`).Scan(&probe)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return classify(err, errDevicesTimeout, errDevicesUnreadable)
	}
	return nil
}

func classify(err, timeout, other error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return timeout
	}
	return other
}

var (
	errDatabaseUnreachable = errors.New("database unreachable")
	errDatabaseTimeout     = errors.New("database timed out")
	errDevicesUnreadable   = errors.New("authz.devices unreadable")
	errDevicesTimeout      = errors.New("authz.devices timed out")
)

func readyReason(err error) string {
	switch {
	case errors.Is(err, errDatabaseUnreachable):
		return "database unreachable"
	case errors.Is(err, errDatabaseTimeout):
		return "database timed out"
	case errors.Is(err, errDevicesUnreadable):
		return "could not read authz.devices"
	case errors.Is(err, errDevicesTimeout):
		return "authz.devices timed out"
	default:
		return "database unavailable"
	}
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
