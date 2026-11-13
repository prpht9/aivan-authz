//go:build integration

package gate_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

// host and target are the values every test signs unless it is testing
// something else.
const (
	testHost   = "aivan-hud.home.arpa"
	testTarget = "/dashboard"
)

// device is one enrolled key plus the row it belongs to.
type device struct {
	ID        [16]byte
	UserID    int64
	Username  string
	Origin    string
	Kind      string
	Alg       string
	PublicKey []byte
	edPriv    ed25519.PrivateKey
	ecPriv    *ecdsa.PrivateKey
}

// sign produces the wire signature for message under the device's algorithm.
func (d device) sign(message string) []byte {
	switch d.Alg {
	case string(proof.AlgorithmEd25519):
		return ed25519.Sign(d.edPriv, []byte(message))
	default:
		digest := sha256.Sum256([]byte(message))
		sig, err := ecdsa.SignASN1(rand.Reader, d.ecPriv, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
}

// env is a running gate against a scratch database.
type env struct {
	t       testing.TB
	service string
	super   string
	pool    *pgxpool.Pool
	counter *store.Counter
	gate    *gate.Gate
	server  *httptest.Server
	client  *http.Client
	logBuf  *logBuffer
	now     time.Time
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newEnv builds the harness database, the fixture users and groups, and a gate
// whose clock the test controls. The gate's log goes to a buffer so a test can
// assert the reason code a decision carried.
func newEnv(t testing.TB) *env {
	return newEnvWithLog(t, newLogBuffer())
}

// logBuffer is a concurrency-safe sink for the gate's JSON log lines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newLogBuffer() *logBuffer { return &logBuffer{} }

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// reasons returns the reason field of every decision line written so far.
func (l *logBuffer) reasons() []string {
	var out []string
	for _, line := range strings.Split(l.String(), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Msg    string `json:"msg"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Msg == "decision" {
			out = append(out, rec.Reason)
		}
	}
	return out
}

// newEnvWithLog is newEnv with an explicit log sink.
func newEnvWithLog(t testing.TB, sink io.Writer) *env {
	t.Helper()
	service, super := harness.Setup(t)

	counter := &store.Counter{}
	db, err := store.Open(context.Background(), service,
		store.WithQueryCounter(counter),
		store.WithStatements(store.GateStatements()...),
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	table := testTable(t)
	var logs *logBuffer
	if sink, ok := sink.(*logBuffer); ok {
		logs = sink
	}
	e := &env{
		t: t, service: service, super: super, pool: db.Pool, counter: counter, logBuf: logs,
		// Truncated to the second so a timestamp and the database's now()
		// agree on the same instant without sub-second races. The app clock is
		// injected and the verifier reads only it for skew; the database clock
		// only decides expiry.
		now: time.Unix(time.Now().Unix(), 0),
	}

	g, err := gate.New(gate.Options{
		Pool:     db.Pool,
		Table:    table,
		Log:      slog.New(slog.NewJSONHandler(sink, nil)),
		NonceTTL: 120 * time.Second,
		Skew:     300 * time.Second,
		MaxBody:  65536,
		// Short enough that an injected clock can cross both bounds inside a
		// test without sleeping, long enough that the 60 s write window and
		// the idle interval are distinct quantities.
		SessionIdle: 15 * time.Minute,
		SessionMax:  8 * time.Hour,
		Counter:     counter,
		Now:         func() time.Time { return e.now },
		Page:        gate.EmbeddedPage(),
	})
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	e.gate = g

	mux := http.NewServeMux()
	mux.HandleFunc("/__aivan/verify", g.Verify)
	mux.HandleFunc("/__aivan/nonce", g.Nonce)
	mux.HandleFunc("/__aivan/session", g.Session)
	mux.HandleFunc(gate.EnrollPath, g.Enroll)
	mux.HandleFunc("/__aivan/enroll/", g.EnrollAsset)
	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)

	// The gate's own redirect target lives on Traefik, not on this server, so
	// a redirect must be observable rather than followed.
	client := e.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	e.client = client
	return e
}

// testTable is the policy the tests run against. /admin is the admin class, /
// and everything else requires an authenticated device.
func testTable(t testing.TB) *policy.Table {
	t.Helper()
	tbl, err := policy.New(map[string]policy.Host{
		testHost: {
			Routes: []policy.Route{
				{Prefix: policy.EnrollmentPrefix, Class: policy.ClassEnrollment},
				{Prefix: "/", Class: policy.ClassAuthenticated},
				{Prefix: "/admin", Class: policy.ClassAdmin},
				{Prefix: "/open", Class: policy.ClassPublic},
			},
		},
		"second.home.arpa": {
			Routes: []policy.Route{
				{Prefix: policy.EnrollmentPrefix, Class: policy.ClassEnrollment},
				{Prefix: "/", Class: policy.ClassAuthenticated},
			},
		},
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return tbl
}

// fixture user and group ids. The fixture is applied by the harness and the
// test owns its rows, so they are stable constants.
const (
	userAlice int64 = 1
	userBob   int64 = 2
)

// seedUsers writes the two users the tests need: alice in admin and free, bob
// in no group at all.
func (e *env) seedUsers() {
	e.t.Helper()
	harness.Exec(e.t, e.super, `
		delete from authz.devices;
		delete from public.groups_users;
		delete from public.groups;
		delete from public.users;
		insert into public.users (id, email, username, active) values
			(1, 'alice@example.invalid', 'alice', true),
			(2, 'bob@example.invalid', 'bob', true),
			(3, 'carol@example.invalid', 'carol', false);
		insert into public.groups (id, name) values (10, 'admin'), (11, 'free');
		insert into public.groups_users (group_id, user_id) values
			(10, 1), (11, 1), (11, 2);
	`)
}

// enroll inserts a device row and returns the key material that signs for it.
func (e *env) enroll(userID int64, origin, kind, alg string) device {
	e.t.Helper()
	d := device{UserID: userID, Username: usernameOf(userID), Origin: origin,
		Kind: kind, Alg: alg}
	if _, err := rand.Read(d.ID[:]); err != nil {
		e.t.Fatalf("device id: %v", err)
	}
	switch alg {
	case string(proof.AlgorithmEd25519):
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			e.t.Fatalf("generate: %v", err)
		}
		d.PublicKey, d.edPriv = pub, priv
	case string(proof.AlgorithmES256):
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			e.t.Fatalf("generate: %v", err)
		}
		d.ecPriv = priv
		d.PublicKey = elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	default:
		e.t.Fatalf("unknown alg %q", alg)
	}

	harness.Exec(e.t, e.super, fmt.Sprintf(`
		insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
		values ('%s', %d, '%s', 'test device', '%s', decode('%x', 'hex'), '%s');
	`, proof.FormatDeviceID(d.ID), userID, origin, kind, d.PublicKey, alg))
	return d
}

func usernameOf(userID int64) string {
	switch userID {
	case userAlice:
		return "alice"
	case userBob:
		return "bob"
	default:
		return "carol"
	}
}

// revoke marks a device revoked.
func (e *env) revoke(d device) {
	e.t.Helper()
	harness.Exec(e.t, e.super, fmt.Sprintf(
		`update authz.devices set revoked_at = now() where id = '%s'`,
		proof.FormatDeviceID(d.ID)))
}

// setActive sets public.users.active for userID.
func (e *env) setActive(userID int64, active bool) {
	e.t.Helper()
	harness.Exec(e.t, e.super, fmt.Sprintf(
		`update public.users set active = %t where id = %d`, active, userID))
}

// nonce inserts a nonce whose lifetime is measured from the database's own
// now(), so an injected application clock cannot make a nonce look expired to
// the gate while the database considers it live. The returned value is the
// nonce as the client would send it.
func (e *env) nonceAt(d device, issuedDelta, expiresDelta time.Duration) string {
	e.t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		e.t.Fatalf("nonce: %v", err)
	}
	hash := proof.SHA256Sum(raw[:])
	harness.Exec(e.t, e.super, fmt.Sprintf(
		`insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
		 values (decode('%x', 'hex'), '%s', now() + interval '%d milliseconds', now() + interval '%d milliseconds')`,
		hash[:], proof.FormatDeviceID(d.ID),
		issuedDelta.Milliseconds(), expiresDelta.Milliseconds()))
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// nonce issues a live nonce, as a client would receive one.
func (e *env) nonce(d device) string {
	e.t.Helper()
	return e.nonceAt(d, -time.Hour, time.Hour)
}

// nonceViaEndpoint issues a nonce the way a client does, so the endpoint and
// the verify path are exercised together.
func (e *env) nonceViaEndpoint(d device) string {
	e.t.Helper()
	body := fmt.Sprintf(`{"device":%q}`, proof.FormatDeviceID(d.ID))
	resp := e.post("/__aivan/nonce", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("nonce endpoint = %d %q, want 200", resp.StatusCode, raw)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("decode nonce: %v", err)
	}
	return out.Nonce
}

// signedRequest is one prepared verify call.
type signedRequest struct {
	Device    device
	Nonce     string
	Timestamp time.Time
	Method    string
	Scheme    string
	Host      string
	Target    string
	Body      string
	Accept    string
	Headers   map[string]string
	// Signer is the key that signs, when it is not the device being claimed.
	// The S14 unknown-device case needs a real signature over an id that has
	// no row.
	Signer *device
}

// signingKey is the device whose private key signs this request.
func (s signedRequest) signingKey() device {
	if s.Signer != nil {
		return *s.Signer
	}
	return s.Device
}

// signatureFor returns the wire signature for this request's canonical string.
func (s signedRequest) signatureFor(e *env) string {
	msg := proof.Canonical(proof.Request{
		Method:     s.method(),
		Scheme:     s.scheme(),
		Host:       s.host(),
		Target:     s.target(),
		BodySHA256: proof.SHA256Hex([]byte(s.Body)),
		Nonce:      s.Nonce,
		Timestamp:  fmt.Sprintf("%d", s.Timestamp.Unix()),
	})
	return base64.RawURLEncoding.EncodeToString(s.signingKey().sign(msg))
}

func (s signedRequest) method() string {
	if s.Method == "" {
		return http.MethodGet
	}
	return s.Method
}
func (s signedRequest) scheme() string {
	if s.Scheme == "" {
		return "https"
	}
	return s.Scheme
}
func (s signedRequest) host() string {
	if s.Host == "" {
		return testHost
	}
	return s.Host
}
func (s signedRequest) target() string {
	if s.Target == "" {
		return testTarget
	}
	return s.Target
}

// request builds the HTTP request a correctly behaving client would send.
func (e *env) request(s signedRequest) *http.Request {
	e.t.Helper()
	method := http.MethodGet
	if s.method() != http.MethodGet {
		method = s.method()
	}
	var body io.Reader
	if s.Body != "" || method == http.MethodPost {
		body = strings.NewReader(s.Body)
	}
	req, err := http.NewRequest(method, e.server.URL+"/__aivan/verify", body)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Method", s.method())
	req.Header.Set("X-Forwarded-Proto", s.scheme())
	req.Header.Set("X-Forwarded-Host", s.host())
	req.Header.Set("X-Forwarded-Uri", s.target())
	// A request with no device is what a client without a proof sends; it
	// carries no proof headers rather than a signature over nothing.
	if s.Device.ID != ([16]byte{}) {
		req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(s.Device.ID))
		req.Header.Set(gate.HeaderNonce, s.Nonce)
		req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
		req.Header.Set(gate.HeaderSignature, s.signatureFor(e))
	}
	if s.Accept != "" {
		req.Header.Set("Accept", s.Accept)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	return req
}

// valid prepares a request that should succeed: a nonce issued one second
// before the request timestamp, and a timestamp at the injected clock.
//
// The nonce is deliberately issued in the past. The database decides issued_at
// from its own now(), which can be sub-second later than the whole-second
// application clock, and a timestamp before issued_at is a denial. One second
// of room makes that ordering explicit instead of lucky.
func (e *env) valid(d device) signedRequest { return e.signedAt(d, e.now) }

// signedAt is valid with an explicit request timestamp.
//
// The nonce is issued an hour early, so that "timestamp is not before
// issued_at" holds for any timestamp a test chooses and for a loop that
// pre-generates thousands of nonces over several seconds. A nonce issued
// relative to the wall clock would drift past the fixed test timestamp and
// turn an unrelated test into a flaky one.
func (e *env) signedAt(d device, ts time.Time) signedRequest {
	e.t.Helper()
	return signedRequest{Device: d, Timestamp: ts, Nonce: e.nonceAt(d, -time.Hour, time.Hour)}
}

// do sends the request and returns the response with its body read.
func (e *env) do(s signedRequest) *response {
	e.t.Helper()
	resp, err := e.server.Client().Do(e.request(s))
	if err != nil {
		e.t.Fatalf("do: %v", err)
	}
	return readResponse(e.t, resp)
}

// parseSetCookie returns the value of the cookie named name from a Set-Cookie
// header, refusing a header that carries any other cookie.
func parseSetCookie(setCookie, name string) (string, error) {
	pair, _, ok := strings.Cut(setCookie, ";")
	if !ok || pair == "" {
		return "", fmt.Errorf("Set-Cookie %q has no cookie", setCookie)
	}
	got, value, ok := strings.Cut(pair, "=")
	if !ok || got != name {
		return "", fmt.Errorf("Set-Cookie names %q, want %q", got, name)
	}
	if value == "" {
		return "", fmt.Errorf("Set-Cookie %q has an empty value", setCookie)
	}
	return value, nil
}

// post sends a body-only request to path, with no proof.
func (e *env) post(path, body string, headers map[string]string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.server.Client().Do(req)
	if err != nil {
		e.t.Fatalf("do: %v", err)
	}
	return resp
}

type response struct {
	Status int
	Body   string
	Header http.Header
}

func readResponse(t testing.TB, resp *http.Response) *response {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return &response{Status: resp.StatusCode, Body: string(body), Header: resp.Header.Clone()}
}

// assertAllowed checks the full identity header set for a successful verify.
func (r *response) assertAllowed(t *testing.T, d device) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d %q, want 200", r.Status, r.Body)
	}
	want := map[string]string{
		gate.HeaderUserID:   fmt.Sprintf("%d", d.UserID),
		gate.HeaderUser:     d.Username,
		gate.HeaderDeviceID: proof.FormatDeviceID(d.ID),
		gate.HeaderProof:    gate.ProofNonce,
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// assertDenied401 checks the constant denial: status, body and the headers a
// client can see. S14 is why the body is compared as a whole.
func (r *response) assertDenied401(t *testing.T) {
	t.Helper()
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d %q, want 401", r.Status, r.Body)
	}
	if got := r.Header.Get("WWW-Authenticate"); got != "Aivan" {
		t.Errorf("WWW-Authenticate = %q, want Aivan", got)
	}
	if !strings.Contains(r.Body, "/__aivan/nonce") {
		t.Errorf("401 body does not name the nonce endpoint: %q", r.Body)
	}
	for _, h := range []string{gate.HeaderUserID, gate.HeaderUser, gate.HeaderRoles,
		gate.HeaderDeviceID, gate.HeaderDeviceKind, gate.HeaderProof} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("401 carried identity header %s: %q", h, v)
		}
	}
}

// harnessAlter runs a superuser statement, for the tests that change the
// schema to simulate a state the constraints would otherwise refuse.
func harnessAlter(t testing.TB, super, sql string) {
	t.Helper()
	harness.Exec(t, super, sql)
}

// harnessExec runs a superuser statement, for tests that age a row directly
// rather than sleeping.
func harnessExec(t testing.TB, super, sql string) {
	t.Helper()
	harness.Exec(t, super, sql)
}

func formatID(id [16]byte) string { return proof.FormatDeviceID(id) }

// session is one minted cookie plus what the client knows about it.
type session struct {
	Cookie string
}

// mintRequest builds a POST to /__aivan/session signed for that path. The
// endpoint is not reached through forwardAuth, so the client sends no
// X-Forwarded-Method: the request itself is the method and target.
func (e *env) mintRequest(d device) *http.Request {
	e.t.Helper()
	nonce := e.nonceAt(d, -time.Hour, time.Hour)
	ts := e.now

	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/__aivan/session", nil)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	msg := proof.Canonical(proof.Request{
		Method:     http.MethodPost,
		Scheme:     "https",
		Host:       testHost,
		Target:     "/__aivan/session",
		BodySHA256: proof.EmptyBodySHA256,
		Nonce:      nonce,
		Timestamp:  fmt.Sprintf("%d", ts.Unix()),
	})
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
	req.Header.Set(gate.HeaderNonce, nonce)
	req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", ts.Unix()))
	req.Header.Set(gate.HeaderSignature, base64.RawURLEncoding.EncodeToString(d.sign(msg)))
	return req
}

// mint exchanges a signed proof for a cookie through POST /__aivan/session,
// the way a browser does, and returns the cookie value.
func (e *env) mint(d device) session {
	e.t.Helper()
	resp, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		e.t.Fatalf("mint: %v", err)
	}
	r := readResponse(e.t, resp)
	if r.Status != http.StatusNoContent {
		e.t.Fatalf("mint status = %d %q, want 204", r.Status, r.Body)
	}
	cookie, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		e.t.Fatalf("mint Set-Cookie: %v", err)
	}
	return session{Cookie: cookie}
}

// verifyWith sends a verify for cookie with no proof headers, which is what a
// browser signed in by cookie does.
func (e *env) verifyWith(cookie string, method, target string) *response {
	e.t.Helper()
	return e.doSessionCookie(signedRequest{Method: method, Target: target}, cookie)
}

// doSessionCookie sends s with a Cookie header and no proof, then returns the
// response.
func (e *env) doSessionCookie(s signedRequest, cookie string) *response {
	e.t.Helper()
	req := e.request(signedRequest{Method: s.Method, Target: s.Target, Headers: s.Headers})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	req.Header.Set("Cookie", gate.SessionCookie+"="+cookie)
	resp, err := e.server.Client().Do(req)
	if err != nil {
		e.t.Fatalf("do: %v", err)
	}
	return readResponse(e.t, resp)
}

// sessionRowFor reads the one session row for a cookie, asserting there is
// exactly one.
func (e *env) sessionRowFor(cookie string) (idle, absolute time.Time, deviceID string) {
	e.t.Helper()
	hash := proof.SHA256Sum([]byte(cookie))
	if err := e.pool.QueryRow(context.Background(), `
select idle_expires_at, absolute_expires_at, device_id::text
  from authz.sessions where token_hash = $1`, hash[:]).Scan(&idle, &absolute, &deviceID); err != nil {
		e.t.Fatalf("read session row: %v", err)
	}
	return idle, absolute, deviceID
}

// sessionsFor counts the sessions of a device.
func (e *env) sessionsFor(d device) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(),
		`select count(*) from authz.sessions where device_id = $1`,
		proof.FormatDeviceID(d.ID)).Scan(&n); err != nil {
		e.t.Fatalf("count sessions: %v", err)
	}
	return n
}

// lastSeen returns the device's last_seen_at, or nil when it has never been
// stamped.
func (e *env) lastSeen(d device) *time.Time {
	e.t.Helper()
	var at *time.Time
	if err := e.pool.QueryRow(context.Background(),
		`select last_seen_at from authz.devices where id = $1`,
		proof.FormatDeviceID(d.ID)).Scan(&at); err != nil {
		e.t.Fatalf("read last_seen_at: %v", err)
	}
	return at
}

// Time helpers, wrapped so the benchmark file does not import time twice.
func timeNow() int64 { return time.Now().UnixNano() }

func timeSince(start int64) int64 { return time.Now().UnixNano() - start }

func microseconds(ns int64) time.Duration { return time.Duration(ns) }

func sortInt64s(v []int64) {
	// Insertion sort is too slow at 2000; a plain sort is clearer than a
	// hand-written quicksort here.
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
}
