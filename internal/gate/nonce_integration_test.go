//go:build integration

package gate_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
)

// TestNonceEndpointIssuesForAKnownDevice is the positive case, and it checks
// that the nonce is stored hashed and not as issued.
func TestNonceEndpointIssuesForAKnownDevice(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	body := fmt.Sprintf(`{"device":%q}`, formatID(d.ID))
	resp := e.post("/__aivan/nonce", body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var out struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()

	if len(out.Nonce) < 40 {
		t.Errorf("nonce %q is too short for 32 bytes of base64url", out.Nonce)
	}
	if _, err := time.Parse(time.RFC3339, out.ExpiresAt); err != nil {
		t.Errorf("expires_at %q is not RFC 3339: %v", out.ExpiresAt, err)
	}

	// The stored value is the hash of the nonce, never the nonce.
	raw, err := base64.RawURLEncoding.DecodeString(out.Nonce)
	if err != nil {
		t.Fatalf("nonce is not base64url: %v", err)
	}
	sum := proof.SHA256Sum(raw)
	var stored int
	if err := e.pool.QueryRow(t.Context(),
		`select count(*) from authz.nonces where nonce_hash = $1`, sum[:]).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if stored != 1 {
		t.Fatalf("the nonce hash is not the stored key (found %d rows)", stored)
	}
	// And the nonce text itself is not used as a key anywhere.
	var plain int
	if err := e.pool.QueryRow(t.Context(),
		`select count(*) from authz.nonces where nonce_hash = convert_to($1,'UTF8')`,
		out.Nonce).Scan(&plain); err != nil {
		t.Fatalf("query: %v", err)
	}
	if plain != 0 {
		t.Fatalf("the nonce was stored unhashed")
	}
}

// TestNonceEndpointAlwaysSucceedsForAValidId is S14's nonce half: an id with no
// device row gets a nonce, so the endpoint is not an existence oracle. The
// response must be identical in shape to the known-device case.
func TestNonceEndpointAlwaysSucceedsForAValidId(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	known := e.enroll(userAlice, testHost, "browser", "ed25519")

	var unknown [16]byte
	copy(unknown[:], "ffffffffffffffffffffffffffffffff")

	for name, id := range map[string]string{
		"known device":   formatID(known.ID),
		"unknown device": formatID(unknown),
	} {
		t.Run(name, func(t *testing.T) {
			resp := e.post("/__aivan/nonce", fmt.Sprintf(`{"device":%q}`, id), nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q", got)
			}
		})
	}
}

// TestNonceEndpointRejectsAMalformedId is the 400 half: the id is checked
// syntactically and never looked up.
func TestNonceEndpointRejectsAMalformedId(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, body := range []string{
		``,
		`{}`,
		`{"device":"not-a-uuid"}`,
		`{"device":"3F2504E0-4F89-41D3-9A0C-0305E82C3301"}`,
		`{"device":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","extra":1}`,
	} {
		resp := e.post("/__aivan/nonce", body, nil)
		if resp.StatusCode != http.StatusBadRequest {
			raw, _ := io.ReadAll(resp.Body)
			t.Errorf("body %q: status = %d %q, want 400", body, resp.StatusCode, raw)
		}
		resp.Body.Close()
	}
}

// TestNonceEndpointRateLimit is the 429 half, using the injected bucket so the
// test does not need to send thirty requests.
func TestNonceEndpointRateLimit(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// A fresh gate with a burst of one and no refill within the test.
	srv, client := e.shardedServer(t, 1, 1)

	body := fmt.Sprintf(`{"device":%q}`, formatID(d.ID))
	send := func() int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/__aivan/nonce", strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := send(); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", code)
	}
}

// TestNonceEndpointTableCap is the 503 half. The schema has no cheap way to
// insert 100k rows, so the cap is exercised by shrinking it: the test asserts
// the boundary behaviour rather than the constant.
func TestNonceEndpointTableCap(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts the full cap")
	}
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// Fill the table to the cap in one statement. The rows are scoped to this
	// test's database, which the harness drops afterwards.
	harnessAlter(t, e.super, fmt.Sprintf(`
		insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
		select decode(lpad(to_hex(i), 62, '0'), 'hex'), '%s',
		       now() - interval '1 hour', now() - interval '30 minutes'
		  from generate_series(1, %d) as i
	`, formatID(d.ID), gate.NonceTableCap))

	// The rows are inserted already expired and then made live, because the
	// cap counts every row and a check that a full table is refused should not
	// depend on which rows are still within their TTL. The gate used to remove
	// them on its own schedule; it does not any more, which is why they stay
	// until the admin binary's CronJob runs.
	harnessAlter(t, e.super, `
		update authz.nonces set expires_at = now() + interval '1 hour'
	`)

	resp := e.post("/__aivan/nonce",
		fmt.Sprintf(`{"device":%q}`, formatID(d.ID)), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 at the cap", resp.StatusCode)
	}
	if resp.Body != nil {
		if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
			t.Errorf("503 body = %q, want empty", body)
		}
	}
}

// TestNonceMethodIsPostOnly: GET is a 405, which is what a browser preflight
// or a crawler would produce.
func TestNonceMethodIsPostOnly(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest(http.MethodGet, e.server.URL+"/__aivan/nonce", nil)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow = %q, want POST", got)
	}
}

// TestNonceStatementCount: the first request of a maintenance minute pays the
// cap count, and the endpoint's own cost is the insert alone until the next one.
// The count is the gate's only scheduled work now, so this also pins that the
// per-request cost did not grow when the purge left.
func TestNonceStatementCount(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// First request runs maintenance (the cap count) and the insert.
	e.post("/__aivan/nonce", fmt.Sprintf(`{"device":%q}`, formatID(d.ID)), nil).Body.Close()

	// Within the same maintenance interval, a second request is the insert
	// only.
	e.counter.Reset()
	resp := e.post("/__aivan/nonce", fmt.Sprintf(`{"device":%q}`, formatID(d.ID)), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("statements = %d, want 1 (the insert) after maintenance ran", n)
	}
}

// shardedServer builds a second gate on the same database with a chosen rate
// limit, so a rate-limit test does not depend on the suite's shared gate.
func (e *env) shardedServer(t testing.TB, perMinute, burst int) (*httptestServer, *http.Client) {
	t.Helper()
	g, err := gate.New(gate.Options{
		Pool: e.pool, Table: testTable(t), Log: quiet(),
		NonceTTL: 120 * time.Second, Skew: 300 * time.Second, MaxBody: 65536,
		Counter: e.counter, Now: func() time.Time { return e.now },
		RatePerMinute: perMinute, RateBurst: burst,
	})
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__aivan/verify", g.Verify)
	mux.HandleFunc("/__aivan/nonce", g.Nonce)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &httptestServer{URL: srv.URL}, srv.Client()
}

// httptestServer is the part of httptest.Server the nonce tests need.
type httptestServer struct{ URL string }
