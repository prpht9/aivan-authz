//go:build integration

package httpx_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/httpx"
	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestReadinessTracksTheDatabase is the B8 item: /readyz is 200 while the
// database answers, 503 as soon as it does not, and 200 again afterwards
// without a restart.
func TestReadinessTracksTheDatabase(t *testing.T) {
	_, service, _ := harness.Setup(t)
	ctx := context.Background()

	db, err := store.Open(ctx, service)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	srv := httptest.NewServer(httpx.NewRouter(db.Pool, quiet()))
	defer srv.Close()

	probe := func(path string) (int, string) {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}

	if code, body := probe("/readyz"); code != http.StatusOK {
		t.Fatalf("readyz with a healthy database = %d %q, want 200", code, body)
	}
	if code, body := probe("/healthz"); code != http.StatusOK {
		t.Fatalf("healthz = %d %q, want 200", code, body)
	}

	// Closing the pool is the closest unit-level stand-in for the database
	// going away: every query from here on fails.
	db.Close()

	code, body := probe("/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with no database = %d %q, want 503", code, body)
	}
	if body == "" || strings.Contains(body, "\n") {
		t.Fatalf("readyz reason is not one line: %q", body)
	}
	if strings.Contains(body, "postgres://") {
		t.Fatalf("readyz leaked the DSN: %q", body)
	}

	// Liveness must not care. A database outage that restarts the pod is an
	// endless restart loop.
	if code, body := probe("/healthz"); code != http.StatusOK {
		t.Fatalf("healthz with no database = %d %q, want 200", code, body)
	}

	// And readiness recovers when the database does, in the same process.
	recovered, err := store.Open(ctx, service)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer recovered.Close()

	recoveredSrv := httptest.NewServer(httpx.NewRouter(recovered.Pool, quiet()))
	defer recoveredSrv.Close()
	resp, err := recoveredSrv.Client().Get(recoveredSrv.URL + "/readyz")
	if err != nil {
		t.Fatalf("get readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("readyz after recovery = %d %q, want 200", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// TestReadinessRequiresDevices proves the second statement matters: a database
// the gate can reach but whose authz schema is missing is not ready, because it
// could not read devices.
func TestReadinessRequiresDevices(t *testing.T) {
	harness.Env(t)
	_, dsn := harness.CreateDatabase(t)
	// No migrations, so authz.devices does not exist.

	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	srv := httptest.NewServer(httpx.NewRouter(db.Pool, quiet()))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz without authz schema = %d %q, want 503", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if got := strings.TrimSpace(string(body)); got != "could not read authz.devices" {
		t.Fatalf("reason = %q, want the devices reason", got)
	}
}
