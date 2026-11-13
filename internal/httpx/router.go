package httpx

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxRequestTime bounds how long the gate may spend on any request. Traefik's
// forwardAuth timeout is a hardcoded 30 s with no configuration field, so the
// only place a shorter bound can live is inside the service (spec §8.2).
const MaxRequestTime = 5 * time.Second

// NewRouter builds the gate's own router. The health endpoints live here and
// are therefore excluded from the forwardAuth chain by construction: they are
// on this server, not on the application's.
func NewRouter(pool *pgxpool.Pool, log *slog.Logger) http.Handler {
	health := &Health{Pool: pool, Log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.HandleFunc("GET /readyz", health.Readiness)

	// Phase C mounts /__aivan/verify and /__aivan/nonce on this same mux.
	var h http.Handler = mux
	h = accessLog(log)(h)
	h = WithRequestID(log)(h)
	h = timeoutMiddleware(MaxRequestTime)(h)
	return h
}

func timeoutMiddleware(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, "request timeout\n")
	}
}
