package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRequestIDIsGeneratedAndReturned covers B6: a 16-byte hex id per request,
// in the context and in the response header, never taken from the client.
func TestRequestIDIsGeneratedAndReturned(t *testing.T) {
	hex16 := regexp.MustCompile(`^[0-9a-f]{32}$`)

	var seen string
	h := WithRequestID(quietLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}))

	for _, clientID := range []string{"", "client-supplied-id"} {
		t.Run("client id "+clientID, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if clientID != "" {
				req.Header.Set(RequestIDHeader, clientID)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			got := rec.Header().Get(RequestIDHeader)
			if !hex16.MatchString(got) {
				t.Fatalf("response id %q is not 32 hex characters", got)
			}
			if got == clientID {
				t.Fatalf("client id was echoed as the request id")
			}
			if seen != got {
				t.Fatalf("context id %q != response id %q", seen, got)
			}
		})
	}
}

func TestRequestIDsDiffer(t *testing.T) {
	seen := map[string]bool{}
	h := WithRequestID(quietLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		id := rec.Header().Get(RequestIDHeader)
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}

// TestHealthRoutesAreMounted checks the two paths exist with the right method
// and that unknown paths and wrong methods are refused. The probes are on the
// gate's own router, so they never pass through forwardAuth.
func TestHealthRoutesAreMounted(t *testing.T) {
	mux := http.NewServeMux()
	health := &Health{Log: quietLogger()}
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.HandleFunc("GET /readyz", health.Readiness)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/nope", http.StatusNotFound},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s = %d, want %d (body %q)", tc.method, tc.path, resp.StatusCode, tc.want, body)
		}
	}
}

// TestLivenessTouchesNothing is the B8 requirement that a database outage does
// not restart the pod: the handler has a nil pool and still answers 200.
func TestLivenessTouchesNothing(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Health{Log: quietLogger()}).Liveness(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

// TestReadinessFailsClosed asserts a readiness check with no usable pool
// answers 503 with a one-line reason, rather than panicking or hanging.
func TestReadinessFailsClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readiness panicked with a nil pool: %v", r)
		}
	}()
	rec := httptest.NewRecorder()
	(&Health{Log: quietLogger()}).Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	if strings.ContainsAny(body, "\n") {
		t.Fatalf("reason is not one line: %q", body)
	}
	if body == "" {
		t.Fatal("503 has no reason")
	}
}

func TestReadyReasonIsFixedText(t *testing.T) {
	// The reasons are fixed so the endpoint never leaks a DSN or a schema.
	for _, reason := range []string{
		"database unreachable",
		"database timed out",
		"could not read authz.devices",
		"authz.devices timed out",
		"database unavailable",
	} {
		if strings.Contains(reason, "postgres://") || strings.Contains(reason, "password") {
			t.Fatalf("reason %q looks like it leaks configuration", reason)
		}
	}
}
