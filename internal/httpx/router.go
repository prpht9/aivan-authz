package httpx

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/gate"
)

// MaxRequestTime bounds how long the gate may spend on any request. Traefik's
// forwardAuth timeout is a hardcoded 30 s with no configuration field, so the
// only place a shorter bound can live is inside the service (spec §8.2).
const MaxRequestTime = 5 * time.Second

// RouterOptions is what the gate's own listeners need. Health is optional so
// the health-only tests keep their existing shape.
type RouterOptions struct {
	Pool   *pgxpool.Pool
	Log    *slog.Logger
	Gate   *gate.Gate
	Health *Health
}

// NewRouter builds the gate's own router. The health endpoints and the
// /__aivan/* endpoints live here and are therefore excluded from the
// forwardAuth chain by construction: they are on this server, not on the
// application's.
//
// A nil Gate mounts health only, which is what the Phase B tests construct.
func NewRouter(pool *pgxpool.Pool, log *slog.Logger) http.Handler {
	return NewRouterWith(RouterOptions{Pool: pool, Log: log})
}

// NewRouterWith mounts the full surface.
func NewRouterWith(o RouterOptions) http.Handler {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	health := o.Health
	if health == nil {
		health = &Health{Pool: o.Pool, Log: o.Log}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.HandleFunc("GET /readyz", health.Readiness)

	if o.Gate != nil {
		// No method in the pattern: preserveRequestMethod forwards the real
		// one, and the gate must answer every method without a panic.
		mux.HandleFunc("/__aivan/verify", o.Gate.Verify)
		mux.HandleFunc("/__aivan/nonce", o.Gate.Nonce)
		// The session endpoints are reached directly, not through forwardAuth,
		// so they live on this router like the others and the handler decides
		// POST from DELETE.
		mux.HandleFunc("/__aivan/session", o.Gate.Session)
		// Enrollment: the page and the claim on one prefix. The claim is the
		// only unauthenticated write path this service has, and the policy
		// class that permits it is pinned to this prefix (policy.New).
		mux.HandleFunc(gate.EnrollPath, o.Gate.Enroll)
		mux.HandleFunc("/__aivan/enroll/", o.Gate.EnrollAsset)
	}

	var h http.Handler = mux
	h = accessLog(o.Log)(h)
	h = WithRequestID(o.Log)(h)
	h = timeoutMiddleware(MaxRequestTime)(h)
	return h
}

func timeoutMiddleware(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, "request timeout\n")
	}
}
