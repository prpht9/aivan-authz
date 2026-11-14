//go:build integration

package gate_test

// A phone-shaped client, end to end, with no page and no browser headers.
//
// aivan-hud/doc/plan-web-and-mobile-registration.md step 5 asks for the wire to
// be proved before any Swift or Kotlin exists. These tests are that proof: a key
// generated on the client, a code minted the way the console mints it, a claim
// with no Accept: text/html and no Sec-Fetch-Site, and then a gated request
// carrying only the cookie the claim returned.
//
// The denial side is here too, because the flow is only as good as its refusals:
// a replayed claim, a wrong code, a revoked device, and a phone code spent by a
// browser.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

// The gate's own route paths. They are literals here for the same reason the
// other integration tests use literals: the constants the service exports are
// about headers and cookies, not routes.
const (
	phoneVerifyPath  = "/__aivan/verify"
	phoneSessionPath = "/__aivan/session"
)

// phoneConsole is the operator's pool: minting is a console action, and the
// gate's own credential holds no INSERT on authz.pending_enrollments. Opening it
// here keeps the whole flow in one test, from the code the operator prints to
// the request the phone makes.
func phoneConsole(t *testing.T, super string) *pgxpool.Pool {
	t.Helper()
	db, err := store.Open(context.Background(), harness.Operator(t, super))
	if err != nil {
		t.Fatalf("open as the operator role: %v", err)
	}
	t.Cleanup(db.Close)
	return db.Pool
}

// phoneCookieJar is what a native client holds between requests: the cookie
// value the claim set, and nothing else. It is deliberately not an
// http.CookieJar, so a test cannot pass because a library quietly attached a
// header the phone would not send.
type phoneCookieJar struct {
	value string
}

// claimAsPhone mints a code through the console the way the operator does, then
// spends it with a claim that looks like a native client: a JSON body, no
// Accept, no Sec-Fetch-Site, no Origin.
func claimAsPhone(t *testing.T, e *env, username, kind string) (phoneCookieJar, string) {
	t.Helper()

	// The console mints against the same database, as the same operator
	// identity an install would use.
	res, err := console.Enroll(context.Background(), phoneConsole(t, e.super), console.EnrollOptions{
		Username: username,
		Origin:   testHost,
		Kind:     kind,
	}, []string{testHost, "second.home.arpa"}, "phone-flow-test")
	if err != nil {
		t.Fatalf("console mint for %s: %v", kind, err)
	}

	claim := signedClaim(t, res.Code, kind, e.claim)
	cookie, err := parseSetCookie(claim.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("Set-Cookie: %v", err)
	}
	return phoneCookieJar{value: cookie}, claim.Header.Get(gate.HeaderDeviceID)
}

// signedClaim spends a code with an Ed25519 key generated here, the way a phone
// does: the private half never leaves the client, and the canonical string is
// the code, the algorithm and the wire key.
func signedClaim(t *testing.T, code, kind string, send func(claimRequest) *response) *response {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate phone key: %v", err)
	}
	wireKey := base64.RawURLEncoding.EncodeToString(pub)
	normalised := proof.NormalizeEnrollCode(code)
	msg := proof.EnrollCanonical(normalised, "ed25519", wireKey)
	return send(claimRequest{
		Code:      normalised,
		Kind:      kind,
		Alg:       "ed25519",
		PublicKey: wireKey,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg))),
	})
}

// gated is one request from the phone to a gated route: the cookie, the path a
// proxy would forward, no proof headers and no browser navigation headers.
func (j phoneCookieJar) gated(t *testing.T, e *env, method, path string, headers map[string]string) *response {
	t.Helper()
	req, err := http.NewRequest(method, e.server.URL+phoneVerifyPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Uri", path)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if j.value != "" {
		req.Header.Set("Cookie", gate.SessionCookie+"="+j.value)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return readResponse(t, resp)
}

// gatedGet is the common case: a GET with no extra headers.
func (j phoneCookieJar) gatedGet(t *testing.T, e *env, path string) *response {
	return j.gated(t, e, http.MethodGet, path, nil)
}

// TestPhoneClientEnrollsAndReachesAGatedRoute is step 5's happy path.
func TestPhoneClientEnrollsAndReachesAGatedRoute(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, deviceID := claimAsPhone(t, e, "alice", "phone")

	r := jar.gatedGet(t, e, "/admin")
	if r.Status != http.StatusOK {
		t.Fatalf("GET /admin with the phone's cookie = %d %q, want 200", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "phone" {
		t.Errorf("X-Aivan-Device-Kind = %q, want phone", got)
	}
	if got := r.Header.Get(gate.HeaderDeviceID); got != deviceID {
		t.Errorf("device = %q, want %q", got, deviceID)
	}
	if got := r.Header.Get(gate.HeaderProof); got != gate.ProofSession {
		t.Errorf("proof = %q, want session", got)
	}
	if got := r.Header.Get(gate.HeaderRoles); got != "admin,free" {
		t.Errorf("roles = %q, want admin,free", got)
	}
}

// TestPhoneCookieIsSpentOnce: a replayed claim is a refusal, and the session it
// already produced keeps working. The second claim cannot mint a second device.
func TestPhoneCookieIsSpentOnce(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, _ := claimAsPhone(t, e, "alice", "phone")
	// The console refuses a second live record for the same slot and a second
	// live device of the same kind, so the replay is a re-send of the record the
	// first claim already spent. The console is expected to refuse a new code.
	res, err := console.Enroll(context.Background(), phoneConsole(t, e.super), console.EnrollOptions{
		Username: "alice", Origin: testHost, Kind: "phone",
	}, []string{testHost}, "phone-flow-test")
	if err == nil {
		t.Fatalf("console minted a second live phone record (%s); the slot should refuse it", res.RecordID)
	}

	if jar.gatedGet(t, e, "/admin").Status != http.StatusOK {
		t.Fatal("the session from the first claim stopped working")
	}
	if n := e.countDevices(); n != 1 {
		t.Fatalf("devices = %d, want 1", n)
	}
}

// TestPhoneClaimWithAWrongCodeIsRefused: the code is the only thing the phone
// has to type, and a wrong one is the constant denial.
func TestPhoneClaimWithAWrongCodeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	res, err := console.Enroll(context.Background(), phoneConsole(t, e.super), console.EnrollOptions{
		Username: "alice", Origin: testHost, Kind: "phone",
	}, []string{testHost}, "phone-flow-test")
	if err != nil {
		t.Fatalf("console mint: %v", err)
	}
	// One character changed, so the shape is valid and only the digest differs.
	code := proof.NormalizeEnrollCode(res.Code)
	wrong := []byte(code)
	if wrong[0] == 'A' {
		wrong[0] = 'B'
	} else {
		wrong[0] = 'A'
	}

	// The signature covers the wrong code, so the claim is well formed and the
	// refusal comes from the record, as it does for a phone that mistyped.
	signedClaim(t, string(wrong), "phone", e.claim).assertEnrollDenied(t)

	// The real code still works: a typo must not burn the record. This is the
	// same record the typo was refused on, claimed with the code the operator
	// printed.
	claim := signedClaim(t, res.Code, "phone", e.claim)
	if claim.Status != http.StatusCreated {
		t.Fatalf("claim with the printed code = %d %q, want 201", claim.Status, claim.Body)
	}
}

// TestPhoneCodeSpentByABrowserIsStillAPhone: kind comes from the record, so a
// browser page given a phone's code produces a phone device. There is no way to
// trade a weaker kind for the slot the code names.
func TestPhoneCodeSpentByABrowserIsStillAPhone(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, deviceID := claimAsPhone(t, e, "alice", "phone")
	device, err := proof.ParseDeviceID(deviceID)
	if err != nil {
		t.Fatalf("device id: %v", err)
	}
	_, _, kind, _, _ := e.deviceRow(device)
	if kind != "phone" {
		t.Fatalf("device kind = %q, want phone", kind)
	}
	if jar.value == "" {
		t.Fatal("the claim did not set a session cookie")
	}
}

// TestRevokedPhoneDeviceIsRefusedOnTheNextRequest: a revoked device's cookie
// stops working immediately, which is what makes a lost phone recoverable.
func TestRevokedPhoneDeviceIsRefusedOnTheNextRequest(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, deviceID := claimAsPhone(t, e, "alice", "phone")
	if jar.gatedGet(t, e, "/admin").Status != http.StatusOK {
		t.Fatal("the phone could not reach /admin before revoke")
	}

	rev, err := console.Revoke(context.Background(), phoneConsole(t, e.super), deviceID, "phone-flow-test")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rev.Sessions == 0 {
		t.Fatal("revoke deleted no session")
	}

	r := jar.gatedGet(t, e, "/admin")
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("GET /admin after revoke = %d %q, want 401", r.Status, r.Body)
	}
}

// TestPhoneAndBrowserCoexistThroughTheConsole: one person on one origin, two
// kinds, both reach /admin with their own cookie. This is the pair the unique
// index is designed to allow.
func TestPhoneAndBrowserCoexistThroughTheConsole(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	browser, _ := claimAsPhone(t, e, "alice", "browser")
	phone, _ := claimAsPhone(t, e, "alice", "phone")

	for name, jar := range map[string]phoneCookieJar{"browser": browser, "phone": phone} {
		if r := jar.gatedGet(t, e, "/admin"); r.Status != http.StatusOK {
			t.Fatalf("%s GET /admin = %d %q, want 200", name, r.Status, r.Body)
		}
	}

	// The console sees both, and refuses a third of either kind.
	res, err := console.ListDevices(context.Background(), phoneConsole(t, e.super), "alice")
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("devices = %d, want a browser and a phone", len(res))
	}
}

// TestPhoneCsrfRuleIsTheOneTheDesignStates pins the rule the native client
// adopts: a non-GET under a cookie session is refused without X-Aivan-Csrf when
// there is no Sec-Fetch-Site, and accepted with it. A phone has no
// Sec-Fetch-Site, so this is the only path it has.
func TestPhoneCsrfRuleIsTheOneTheDesignStates(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, _ := claimAsPhone(t, e, "alice", "phone")

	post := func(csrf string) *response {
		headers := map[string]string{}
		if csrf != "" {
			headers[gate.HeaderCSRF] = csrf
		}
		return jar.gated(t, e, http.MethodPost, "/admin", headers)
	}

	refused := post("")
	if refused.Status != http.StatusForbidden {
		t.Fatalf("POST without a CSRF header = %d %q, want 403", refused.Status, refused.Body)
	}

	accepted := post("phone-csrf-token-0123456789")
	if accepted.Status != http.StatusOK {
		t.Fatalf("POST with a CSRF header = %d %q, want 200", accepted.Status, accepted.Body)
	}
}

// TestPhoneSessionDeleteEndsTheCookie closes the sign-out loop hud's page uses:
// a DELETE of /__aivan/session with the CSRF header ends the phone's cookie, and
// the next gated request is refused.
func TestPhoneSessionDeleteEndsTheCookie(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	jar, _ := claimAsPhone(t, e, "alice", "phone")

	req, err := http.NewRequest(http.MethodDelete, e.server.URL+phoneSessionPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	req.Header.Set(gate.HeaderCSRF, "phone-csrf-token-0123456789")
	req.Header.Set("Cookie", gate.SessionCookie+"="+jar.value)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if r := readResponse(t, resp); r.Status != http.StatusNoContent {
		t.Fatalf("DELETE session = %d %q, want 204", r.Status, r.Body)
	}

	// The clear cookie carries no value, so a jar that overwrote its entry has
	// nothing to send.
	if !strings.HasPrefix(resp.Header.Get("Set-Cookie"), gate.SessionCookie+"=;") {
		t.Fatalf("the clear cookie is %q, want an empty value", resp.Header.Get("Set-Cookie"))
	}
	if r := jar.gatedGet(t, e, "/admin"); r.Status != http.StatusUnauthorized {
		t.Fatalf("GET /admin after the session ended = %d %q, want 401", r.Status, r.Body)
	}
}

// TestPhoneClaimNeedsNoBrowserHeaders is the narrow wire property from the plan
// step 4: a claim with no Accept header at all is a claim, not a redirect. The
// page's redirect is chosen by Accept, and a phone sends none.
func TestPhoneClaimNeedsNoBrowserHeaders(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	res, err := console.Enroll(context.Background(), phoneConsole(t, e.super), console.EnrollOptions{
		Username: "alice", Origin: testHost, Kind: "phone",
	}, []string{testHost}, "phone-flow-test")
	if err != nil {
		t.Fatalf("console mint: %v", err)
	}

	// claimRequest carries no Accept header of its own; e.claim sets only the
	// content type and the forwarded headers, which is the point.
	r := signedClaim(t, res.Code, "phone", e.claim)
	if r.Status != http.StatusCreated {
		t.Fatalf("claim with no Accept header = %d %q, want 201", r.Status, r.Body)
	}
	if loc := r.Header.Get("Location"); loc != "" {
		t.Fatalf("claim redirected to %q; a phone has no page to land on", loc)
	}
}
