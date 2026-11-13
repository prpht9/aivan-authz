package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type requestIDKey struct{}

// RequestIDHeader is the response header carrying the request id. Phase C
// returns it to the application as X-Aivan-Request-Id; here it appears in logs
// only.
const RequestIDHeader = "X-Aivan-Request-Id"

// RequestIDFrom returns the id attached to ctx, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// WithRequestID generates a 16-byte hex id for every request, puts it in the
// context and in the response header. The id is generated, never read from the
// client.
func WithRequestID(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var raw [16]byte
			if _, err := rand.Read(raw[:]); err != nil {
				// crypto/rand failing is fatal for the design; a request id
				// is not worth serving without one.
				log.Error("request id: entropy unavailable", "error", err)
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			id := hex.EncodeToString(raw[:])
			w.Header().Set(RequestIDHeader, id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
		})
	}
}

// accessLog logs one line per request at debug level. Health checks are noisy
// at info, and the decision log in Phase C carries the real content.
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
