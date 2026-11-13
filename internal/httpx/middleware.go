package httpx

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/chris/aivan-authz/internal/reqid"
)

// RequestIDHeader is the response header carrying the request id. Phase C
// returns it to the application as X-Aivan-Request-Id; the generator lives in
// internal/reqid so the authorization path and this package share one value.
const RequestIDHeader = reqid.Header

// RequestIDFrom returns the id attached to ctx, or "".
func RequestIDFrom(ctx context.Context) string { return reqid.From(ctx) }

// WithRequestID generates a 16-byte hex id for every request, puts it in the
// context and in the response header.
func WithRequestID(log *slog.Logger) func(http.Handler) http.Handler {
	return reqid.WithRequestID(log)
}

// accessLog logs one line per request at debug level. Health checks are noisy
// at info, and the gate's decision log carries the real content.
func accessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			log.Debug("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFrom(r.Context()),
			)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
