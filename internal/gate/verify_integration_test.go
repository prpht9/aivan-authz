//go:build integration

package gate_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
)

// TestValidProofIsAllowed is the happy path every other test contrasts with:
// one statement, the identity headers, and no panic.
func TestValidProofIsAllowed(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	e.counter.Reset()
	r := e.do(e.valid(d))
	r.assertAllowed(t, d)

	if got := r.Header.Get(gate.HeaderRoles); got != "admin,free" {
		t.Errorf("roles = %q, want admin,free", got)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "browser" {
		t.Errorf("device kind = %q, want browser", got)
	}
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("statements = %d, want exactly 1 per successful verify", n)
	}
}

// TestAllMethodsAreAnswered is C10's "every method, including HEAD and
// OPTIONS, without a panic".
func TestAllMethodsAreAnswered(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, "PROPFIND"} {
		t.Run(method, func(t *testing.T) {
			s := e.valid(d)
			s.Method = method
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				s.Body = `{"a":1}`
			}
			r := e.do(s)
			r.assertAllowed(t, d)
		})
	}
}

// TestS1ReplayIsRefused: a nonce is single-use, and the second use loses the
// delete race rather than being filtered afterwards.
func TestS1ReplayIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	e.do(s).assertAllowed(t, d)

	replay := e.do(s)
	replay.assertDenied401(t)

	// The nonce is gone: the first request consumed it.
	var count int
	if err := e.pool.QueryRow(t.Context(),
		`select count(*) from authz.nonces`).Scan(&count); err != nil {
		t.Fatalf("count nonces: %v", err)
	}
	if count != 0 {
		t.Fatalf("nonces remaining = %d, want 0", count)
	}
}

// TestS3ExpiredNonceIsRefused: a nonce past expires_at is refused even though
// its hash is still a primary-key hit.
func TestS3ExpiredNonceIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Nonce = e.nonceAt(d, -2*time.Minute, -time.Second)
	e.do(s).assertDenied401(t)
}

// TestS4SkewWindow checks both edges of the window and the boundary itself.
func TestS4SkewWindow(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	cases := []struct {
		name   string
		offset time.Duration
		allow  bool
	}{
		{"inside past", -60 * time.Second, true},
		{"exactly at the past boundary", -300 * time.Second, true},
		{"one second past the boundary", -301 * time.Second, false},
		{"inside future", 60 * time.Second, true},
		{"exactly at the future boundary", 300 * time.Second, true},
		{"one second past the future boundary", 301 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The nonce is issued before the request timestamp, so the
			// "before issued_at" rule does not mask the skew rule.
			s := e.signedAt(d, e.now.Add(tc.offset))

			r := e.do(s)
			if tc.allow {
				r.assertAllowed(t, d)
				return
			}
			r.assertDenied401(t)
		})
	}
}

// TestS4TimestampBeforeNonceIssuance: a signature cannot be older than the
// nonce that made it possible.
func TestS4TimestampBeforeNonceIssuance(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Timestamp = e.now.Add(-90 * time.Second)            // inside the skew window
	s.Nonce = e.nonceAt(d, -time.Minute, 120*time.Second) // issued after the timestamp
	e.do(s).assertDenied401(t)
}

// TestS21DeviceIsBoundToItsOrigin: a key enrolled on one host is refused on
// another even with a valid signature for that other host.
func TestS21DeviceIsBoundToItsOrigin(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// A correctly signed request, for the other configured host.
	s := e.valid(d)
	s.Host = "second.home.arpa"
	e.do(s).assertDenied401(t)

	// And the same device still works on its own host.
	e.do(e.valid(d)).assertAllowed(t, d)
}

// TestRevokedDeviceIsRefused covers the device half of S5 that exists in this
// phase.
func TestRevokedDeviceIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")
	e.revoke(d)

	e.do(e.valid(d)).assertDenied401(t)
}

// TestS7UserWithoutGroupsIsRefusedOnAdmin: bob is active with no admin role,
// so an admin route is a 403 and not a 401.
func TestS7UserWithoutGroupsIsRefusedOnAdmin(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	bob := e.enroll(userBob, testHost, "browser", "ed25519")

	s := e.valid(bob)
	s.Target = "/admin"
	r := e.do(s)
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d %q, want 403", r.Status, r.Body)
	}
	if r.Body != "" {
		t.Errorf("403 body = %q, want empty", r.Body)
	}
	for _, h := range []string{gate.HeaderUserID, gate.HeaderRoles} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("403 carried %s = %q", h, v)
		}
	}

	// The same user on a non-admin route is fine, so the refusal is about the
	// role and not about bob.
	e.do(e.valid(bob)).assertAllowed(t, bob)
}

// TestS7AdminRoleAdmits checks the positive half: alice has admin.
func TestS7AdminRoleAdmits(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	alice := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(alice)
	s.Target = "/admin/users"
	e.do(s).assertAllowed(t, alice)
}

// TestS8IdentityCannotBeSpoofedByHeaders: the gate never reads an identity
// header, so a device of user A presenting user B is still user A.
func TestS8IdentityCannotBeSpoofedByHeaders(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	alice := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(alice)
	s.Target = "/admin"
	s.Headers = map[string]string{
		gate.HeaderUser:     "bob",
		gate.HeaderUserID:   "2",
		gate.HeaderRoles:    "",
		gate.HeaderDeviceID: proof.FormatDeviceID(alice.ID),
		"X-Aivan-Session":   "forged",
		"X-Aivan-Proof":     "session",
	}
	r := e.do(s)
	// Alice keeps her own identity and her own admin role; the forged values
	// change nothing.
	r.assertAllowed(t, alice)
	if got := r.Header.Get(gate.HeaderUser); got != "alice" {
		t.Fatalf("username = %q, want alice", got)
	}
	if got := r.Header.Get(gate.HeaderRoles); got != "admin,free" {
		t.Fatalf("roles = %q, want admin,free", got)
	}
	if got := r.Header.Get("X-Aivan-Session"); got != "" {
		t.Fatalf("X-Aivan-Session was set: %q", got)
	}
}

// TestInactiveUserIsRefused is the user half of the checks before the
// signature.
func TestInactiveUserIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	carol := e.enroll(3, testHost, "browser", "ed25519")
	e.do(e.valid(carol)).assertDenied401(t)
}

// TestS17AlgorithmNotOnTheListIsRefused: the algorithm comes from the device
// row, so a row the schema cannot even hold is simulated by a bad alg value
// written past the check constraint's knowledge. Nothing else in the request
// can choose it.
func TestS17AlgorithmNotOnTheListIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// The schema's check constraint already refuses an unknown alg on insert,
	// which is the first line of defence. To prove the gate also refuses one,
	// relax the constraint for this test's database only.
	harnessAlter(t, e.super, `
		alter table authz.devices drop constraint devices_alg_check;
		alter table authz.devices add constraint devices_alg_check check (true);
	`)
	harnessAlter(t, e.super, fmt.Sprintf(
		`update authz.devices set alg = 'rs256' where id = '%s'`, proof.FormatDeviceID(d.ID)))

	r := e.do(e.valid(d))
	r.assertDenied401(t)

	// The denial is attributed to the algorithm on the device row, which is
	// what gives an operator a reason to look. A handler that skipped this
	// check would still refuse the request, through the library error, but the
	// reason would be indistinguishable from a bad signature.
	if got := e.logBuf.reasons(); len(got) == 0 || got[len(got)-1] != string(gate.ReasonAlgUnsupported) {
		t.Fatalf("decision reasons = %v, want the last to be %q", got, gate.ReasonAlgUnsupported)
	}
}

// TestS14AllDenialsAreIdentical asserts the full response equality S14 wants.
// Every 401 case must be indistinguishable: same status, same body length,
// same header set and values.
func TestS14AllDenialsAreIdentical(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	alice := e.enroll(userAlice, testHost, "browser", "ed25519")
	bob := e.enroll(userBob, testHost, "browser", "ed25519")

	revoked := e.enroll(userAlice, testHost, "phone", "ed25519")
	e.revoke(revoked)

	other := e.enroll(userAlice, "second.home.arpa", "browser", "ed25519")

	expiredNonce := e.nonceAt(alice, -2*time.Minute, -time.Second)

	badSignature := e.valid(alice)
	badSignatureSignature := badSignature.signatureFor(e)

	// A correctly signed request whose device id has no row: the signature is
	// alice's, the claimed id is not.
	unknownDevice := e.valid(alice)
	var randomID [16]byte
	copy(randomID[:], "0123456789abcdef")
	signer := alice
	unknownDevice.Signer = &signer
	unknownDevice.Device = device{ID: randomID, UserID: userAlice, Username: "alice",
		Origin: testHost, Kind: "browser", Alg: "ed25519"}

	cases := []struct {
		name string
		req  func() *response
	}{
		{"no proof headers at all", func() *response {
			req := e.request(e.valid(alice))
			for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
				req.Header.Del(h)
			}
			resp, err := e.server.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			return readResponse(t, resp)
		}},
		{"partial proof headers", func() *response {
			req := e.request(e.valid(alice))
			req.Header.Del(gate.HeaderSignature)
			resp, err := e.server.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			return readResponse(t, resp)
		}},
		{"nonce unknown", func() *response {
			s := e.valid(alice)
			s.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return e.do(s)
		}},
		{"nonce expired", func() *response {
			s := e.valid(alice)
			s.Nonce = expiredNonce
			return e.do(s)
		}},
		{"nonce replayed", func() *response {
			s := e.valid(alice)
			e.do(s).assertAllowed(t, alice)
			return e.do(s)
		}},
		{"timestamp skewed", func() *response {
			return e.do(e.signedAt(alice, e.now.Add(10*time.Minute)))
		}},
		{"wrong origin", func() *response {
			s := e.valid(other)
			s.Host = testHost
			return e.do(s)
		}},
		{"revoked device", func() *response {
			return e.do(e.valid(revoked))
		}},
		{"bad signature", func() *response {
			req := e.request(e.valid(alice))
			// A well-formed signature by the wrong message.
			req.Header.Set(gate.HeaderSignature, badSignatureSignature[:len(badSignatureSignature)-4]+"AAAA")
			resp, err := e.server.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			return readResponse(t, resp)
		}},
		{"device unknown", func() *response {
			return e.do(unknownDevice)
		}},
	}

	var first *response
	var firstName string
	for _, tc := range cases {
		got := tc.req()
		got.assertDenied401(t)
		if first == nil {
			first, firstName = got, tc.name
			continue
		}
		if got.Status != first.Status {
			t.Errorf("%s: status %d != %s's %d", tc.name, got.Status, firstName, first.Status)
		}
		if got.Body != first.Body {
			t.Errorf("%s: body %q != %s's %q", tc.name, got.Body, firstName, first.Body)
		}
		if len(got.Body) != len(first.Body) {
			t.Errorf("%s: body length %d != %s's %d", tc.name, len(got.Body), firstName, len(first.Body))
		}
		if diff := headerDiff(first.Header, got.Header); diff != "" {
			t.Errorf("%s: response headers differ from %s's: %s", tc.name, firstName, diff)
		}
	}

	_ = bob
}

// headerDiff names the first header that differs in name or value, ignoring
// the per-request id, which is generated per request by design.
func headerDiff(a, b http.Header) string {
	names := map[string]bool{}
	for k := range a {
		names[k] = true
	}
	for k := range b {
		names[k] = true
	}
	for k := range names {
		if k == gate.HeaderRequestID {
			continue
		}
		av, bv := a.Get(k), b.Get(k)
		if av != bv {
			return fmt.Sprintf("%s: %q vs %q", k, av, bv)
		}
	}
	return ""
}

// TestNoProofHTMLGetsARedirect: the Accept split, and never on a POST.
//
// The redirect names the login page: a browser that arrives with no cookie may
// be unenrolled or may have lapsed, and only the page that can read the stored
// key tells them apart.
func TestNoProofHTMLGetsARedirect(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	req := e.request(signedRequest{Target: "/admin/users?x=1", Accept: "text/html,application/xhtml+xml"})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusFound {
		t.Fatalf("status = %d %q, want 302", r.Status, r.Body)
	}
	want := "/__aivan/login?rd=" + "%2Fadmin%2Fusers%3Fx%3D1"
	if got := r.Header.Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}

	// The same HTML request as a POST is a 401: a redirect would lose the body.
	post := e.request(signedRequest{Method: http.MethodPost, Target: "/admin", Accept: "text/html", Body: "x"})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		post.Header.Del(h)
	}
	resp, err = e.client.Do(post)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertDenied401(t)
}

// TestPublicRouteAllowsWithoutProof checks the public class: no proof, no
// identity headers.
func TestPublicRouteAllowsWithoutProof(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	req := e.request(signedRequest{Target: "/open"})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	for _, h := range []string{gate.HeaderUserID, gate.HeaderUser, gate.HeaderRoles, gate.HeaderProof} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("public route set %s = %q", h, v)
		}
	}
	if n := e.counter.Value(); n != 0 {
		t.Fatalf("public route issued %d statements, want 0", n)
	}
}

// TestUncoveredPathDefaultsToAuthenticated covers the policy default end to
// end: an unmatched path needs a proof.
func TestUncoveredPathDefaultsToAuthenticated(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	req := e.request(signedRequest{Target: "/nowhere"})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertDenied401(t)
}

// TestHostOutsideConfigIsRefused: a host the gate does not serve never reaches
// the signature check.
func TestHostOutsideConfigIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Host = "evil.example"
	s.Host = "evil.example"
	// The request must still carry a host the table knows, or the target
	// cannot be signed; the gate refuses before that.
	r := e.do(s)
	if r.Status == http.StatusOK {
		t.Fatalf("an unconfigured host was allowed")
	}
}

// TestPlainHTTPIsRefused is C1: a request arriving as http is refused before
// the canonical string is built.
func TestPlainHTTPIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Scheme = "http"
	r := e.do(s)
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d %q, want 403", r.Status, r.Body)
	}
	if n := e.counter.Value(); n != 0 {
		t.Fatalf("plaintext request issued %d statements, want 0", n)
	}
}

// TestZeroStatementsForRejectedBeforeDatabase is C4's second counter item.
func TestZeroStatementsForRejectedBeforeDatabase(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	e.counter.Reset()
	// No proof headers: refused before the database.
	req := e.request(signedRequest{Target: "/dashboard"})
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertDenied401(t)

	if n := e.counter.Value(); n != 0 {
		t.Fatalf("statements = %d, want 0", n)
	}
}

// TestBodyOverMaxIsRefused is the 413 path, even though Phase G owns the
// dedicated S18 test.
func TestBodyOverMaxIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = strings.Repeat("x", 70000)
	r := e.do(s)
	if r.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d %q, want 413", r.Status, r.Body)
	}
	if r.Body != "" {
		t.Errorf("413 body = %q, want empty", r.Body)
	}
}

// TestBodyIsCoveredByTheSignature: changing the body without resigning is
// refused, which is what makes the body hash worth computing.
func TestBodyIsCoveredByTheSignature(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = `{"amount":1}`

	req := e.request(s)
	// Swap the body after signing.
	req.Body = http.NoBody
	req, _ = http.NewRequest(http.MethodPost, req.URL.String(), strings.NewReader(`{"amount":1000}`))
	req.Header.Set("X-Forwarded-Method", s.Method)
	req.Header.Set("X-Forwarded-Proto", s.scheme())
	req.Header.Set("X-Forwarded-Host", s.host())
	req.Header.Set("X-Forwarded-Uri", s.target())
	req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
	req.Header.Set(gate.HeaderNonce, s.Nonce)
	req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
	req.Header.Set(gate.HeaderSignature, s.signatureFor(e))

	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertDenied401(t)
}
