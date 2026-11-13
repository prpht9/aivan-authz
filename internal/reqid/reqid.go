// Package reqid generates the request id the gate returns as
// X-Aivan-Request-Id and logs with every decision. It is its own package
// because both the HTTP wiring and the authorization path need it, and a
// dependency from one to the other would be a cycle.
package reqid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
)

// Header carries the id to the application and to the operator.
const Header = "X-Aivan-Request-Id"

type key struct{}

// From returns the id attached to ctx, or "".
func From(ctx context.Context) string {
	id, _ := ctx.Value(key{}).(string)
	return id
}

// New returns a 32-character hex id. It is generated, never read from the
// client.
func New() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// WithRequestID stamps every request and its response with a fresh id.
func WithRequestID(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := New()
			if err != nil {
				// Entropy failing is fatal for the design; a request id is
				// not worth serving without one.
				log.Error("request id: entropy unavailable", "error", err)
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set(Header, id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), key{}, id)))
		})
	}
}
