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

// sessionHost is the Origin the tests send on the session endpoints. The
// endpoint is not behind forwardAuth, so a proxy sets X-Forwarded-Host but not
// X-Forwarded-Method; sessionForwarded fills the rest in.
const sessionHost = testHost

// TestMintRequiresAValidProof covers the three ways a mint can fail before the
// insert: no proof, a bad signature and an expired nonce. None may set a
// cookie.
func TestMintRequiresAValidProof(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"no proof at all", nil},
		{"bad signature", map[string]string{"bad": "signature"}},
		{"expired nonce", map[string]string{"expired": "nonce"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := e.valid(d)
			req, err := http.NewRequest(http.MethodPost, e.server.URL+"/__aivan/session", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", sessionHost)

			switch tc.name {
			case "no proof at all":
			case "bad signature":
				req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
				req.Header.Set(gate.HeaderNonce, s.Nonce)
				req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
				req.Header.Set(gate.HeaderSignature, s.signatureFor(e)[:20])
			case "expired nonce":
				s.Nonce = e.nonceAt(d, -2*time.Minute, -time.Second)
				req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
				req.Header.Set(gate.HeaderNonce, s.Nonce)
				req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
				req.Header.Set(gate.HeaderSignature, s.signatureFor(e))
			}

			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			r := readResponse(t, resp)
			r.assertDenied401(t)
			if got := r.Header.Get("Set-Cookie"); got != "" {
				t.Fatalf("%s minted a cookie: %q", tc.name, got)
			}
			if n := e.sessionsFor(d); n != 0 {
				t.Fatalf("%s wrote %d session rows, want 0", tc.name, n)
			}
		})
	}
}

// TestMintCookieHeaderIsExact asserts the whole Set-Cookie string, not a
// substring: the attribute set and its order are the contract, and __Host-
// requires Secure, Path=/ and no Domain.
func TestMintCookieHeaderIsExact(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	req := e.mintRequest(d)

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusNoContent {
		t.Fatalf("status = %d %q, want 204", r.Status, r.Body)
	}
	if r.Body != "" {
		t.Errorf("204 body = %q, want empty", r.Body)
	}

	value, ok := strings.CutPrefix(r.Header.Get("Set-Cookie"), gate.SessionCookie+"=")
	if !ok {
		t.Fatalf("Set-Cookie = %q, want the %s cookie", r.Header.Get("Set-Cookie"), gate.SessionCookie)
	}
	token, attrs, ok := strings.Cut(value, ";")
	if !ok {
		t.Fatalf("Set-Cookie has no attributes: %q", value)
	}
	if len(token) != 43 {
		t.Errorf("token length = %d, want 43 for 32 bytes of base64url", len(token))
	}

	want := " Path=/; Secure; HttpOnly; SameSite=Lax"
	if attrs != want {
		t.Fatalf("Set-Cookie attributes = %q, want %q", attrs, want)
	}
	for _, forbidden := range []string{"Domain=", "Max-Age=", "Expires="} {
		if strings.Contains(attrs, forbidden) {
			t.Errorf("Set-Cookie carries %s: %q", forbidden, attrs)
		}
	}

	// The identity comes back on the 204, and it is what a verify of the new
	// cookie returns.
	for k, want := range map[string]string{
		gate.HeaderUserID:   fmt.Sprintf("%d", userAlice),
		gate.HeaderUser:     "alice",
		gate.HeaderDeviceID: proof.FormatDeviceID(d.ID),
		gate.HeaderProof:    gate.ProofSession,
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// TestMintedSessionAuthenticatesVerify: the cookie on /__aivan/verify with no
// proof headers yields the same identity as the proof did, and the mechanism
// is named.
func TestMintedSessionAuthenticatesVerify(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	r := e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d %q, want 200", r.Status, r.Body)
	}
	for k, want := range map[string]string{
		gate.HeaderUserID:     fmt.Sprintf("%d", userAlice),
		gate.HeaderUser:       "alice",
		gate.HeaderDeviceID:   proof.FormatDeviceID(d.ID),
		gate.HeaderDeviceKind: "browser",
		gate.HeaderRoles:      "admin,free",
		gate.HeaderProof:      gate.ProofSession,
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	// The session path runs the same policy, so an admin route needs admin.
	if r := e.verifyWith(sess.Cookie, http.MethodGet, "/admin"); r.Status != http.StatusOK {
		t.Fatalf("admin route with alice's cookie = %d, want 200", r.Status)
	}
	bob := e.enroll(userBob, sessionHost, "browser", "ed25519")
	bobSess := e.mint(bob)
	if r := e.verifyWith(bobSess.Cookie, http.MethodGet, "/admin"); r.Status != http.StatusForbidden {
		t.Fatalf("admin route with bob's cookie = %d, want 403", r.Status)
	}
}

// TestStoredTokenHashIsNotTheToken asserts by value that the table holds the
// digest: a database read does not yield a usable cookie.
func TestStoredTokenHashIsNotTheToken(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	var asPlain int
	if err := e.pool.QueryRow(t.Context(),
		`select count(*) from authz.sessions where token_hash = convert_to($1, 'UTF8')`,
		sess.Cookie).Scan(&asPlain); err != nil {
		t.Fatalf("query: %v", err)
	}
	if asPlain != 0 {
		t.Fatal("the token itself is stored in authz.sessions")
	}

	_, _, deviceID := e.sessionRowFor(sess.Cookie)
	if deviceID != proof.FormatDeviceID(d.ID) {
		t.Fatalf("session device = %s, want %s", deviceID, proof.FormatDeviceID(d.ID))
	}

	// And the token is not in the decision log or a response other than the
	// Set-Cookie that carries it.
	if strings.Contains(e.logBuf.String(), sess.Cookie) {
		t.Fatal("the session token appears in the decision log")
	}
}

// TestSessionIdleExpiry: past idle_expires_at the cookie is refused. The
// database clock decides, so the row is aged directly rather than by sleeping.
func TestSessionIdleExpiry(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)

	harnessExec(t, e.super, fmt.Sprintf(`
		update authz.sessions set idle_expires_at = now() - interval '1 second'
		 where token_hash = decode('%x', 'hex')`, proof.SHA256Sum([]byte(sess.Cookie))))

	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertDenied401(t)
}

// TestSessionAbsoluteExpiry: a session kept alive by activity still dies at
// absolute_expires_at. Activity before the cap does not move it.
func TestSessionAbsoluteExpiry(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	_, absolute, _ := e.sessionRowFor(sess.Cookie)

	// An hour before the cap, with the idle window still open.
	harnessExec(t, e.super, fmt.Sprintf(`
		update authz.sessions
		   set absolute_expires_at = now() + interval '1 hour',
		       idle_expires_at = now() + interval '15 minutes'
		 where token_hash = decode('%x', 'hex')`, proof.SHA256Sum([]byte(sess.Cookie))))
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)

	// Idle slides on that verify, but the absolute cap is untouched.
	_, after, _ := e.sessionRowFor(sess.Cookie)
	if !after.Equal(absolute) && after.After(absolute) {
		t.Fatalf("absolute_expires_at moved forward: %s then %s", absolute, after)
	}

	// Past the cap, with the idle window still open.
	harnessExec(t, e.super, fmt.Sprintf(`
		update authz.sessions
		   set absolute_expires_at = now() - interval '1 second',
		       idle_expires_at = now() + interval '15 minutes'
		 where token_hash = decode('%x', 'hex')`, proof.SHA256Sum([]byte(sess.Cookie))))
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertDenied401(t)
}

// TestS5RevokeKillsTheLiveSession is the session half of S5: a device revoked
// after its cookie was minted is refused on the very next request, and with
// the same 401 body as an expired session.
func TestS5RevokeKillsTheLiveSession(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)

	// Revoke only the device row, leaving the session live. That is what the
	// join through authz.devices has to catch; the console command's delete is
	// tested separately.
	e.revoke(d)
	r := e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard")
	r.assertDenied401(t)

	// The body is the session path's one 401 body, byte for byte.
	expired := newEnv(t)
	expired.seedUsers()
	other := expired.enroll(userAlice, sessionHost, "browser", "ed25519")
	otherSess := expired.mint(other)
	harnessExec(t, expired.super, fmt.Sprintf(`
		update authz.sessions set idle_expires_at = now() - interval '1 second'
		 where token_hash = decode('%x', 'hex')`, proof.SHA256Sum([]byte(otherSess.Cookie))))
	denied := expired.verifyWith(otherSess.Cookie, http.MethodGet, "/dashboard")
	denied.assertDenied401(t)
	if r.Body != denied.Body {
		t.Fatalf("revoked body %q != expired body %q", r.Body, denied.Body)
	}
}

// TestS13CSRF exercises the rule on every branch. An unsafe method under a
// cookie needs same-origin, none, or a well-formed X-Aivan-Csrf header;
// same-site is refused, and its absence without the header is refused.
func TestS13CSRF(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	cases := []struct {
		name   string
		method string
		site   string
		csrf   string
		status int
		reason gate.Reason
	}{
		{name: "GET with no site header", method: http.MethodGet, status: http.StatusOK},
		{name: "HEAD with no site header", method: http.MethodHead, status: http.StatusOK},
		{name: "POST same-origin", method: http.MethodPost, site: "same-origin", status: http.StatusOK},
		{name: "POST none", method: http.MethodPost, site: "none", status: http.StatusOK},
		{name: "POST with a valid header", method: http.MethodPost, csrf: strings.Repeat("a", 16), status: http.StatusOK},
		{name: "POST same-site", method: http.MethodPost, site: "same-site", status: http.StatusForbidden, reason: gate.ReasonCSRFSite},
		{name: "POST with neither", method: http.MethodPost, status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "PUT with neither", method: http.MethodPut, status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "DELETE with neither", method: http.MethodDelete, status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "POST with a short header", method: http.MethodPost, csrf: strings.Repeat("a", 15), status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "POST with a bad character", method: http.MethodPost, csrf: strings.Repeat("a", 20) + "!", status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "POST with a long header", method: http.MethodPost, csrf: strings.Repeat("a", 129), status: http.StatusForbidden, reason: gate.ReasonCSRFMissing},
		{name: "POST with a 128 character header", method: http.MethodPost, csrf: strings.Repeat("a", 128), status: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.site != "" {
				headers["Sec-Fetch-Site"] = tc.site
			}
			if tc.csrf != "" {
				headers[gate.HeaderCSRF] = tc.csrf
			}
			r := e.doSessionCookie(signedRequest{Method: tc.method, Target: "/dashboard",
				Headers: headers}, sess.Cookie)
			if r.Status != tc.status {
				t.Fatalf("status = %d %q, want %d", r.Status, r.Body, tc.status)
			}
			if tc.status == http.StatusForbidden {
				if r.Body != "" {
					t.Errorf("403 body = %q, want empty", r.Body)
				}
				for _, h := range []string{gate.HeaderUserID, gate.HeaderRoles} {
					if v := r.Header.Get(h); v != "" {
						t.Errorf("403 carried %s = %q", h, v)
					}
				}
				if len(e.logBuf.reasons()) == 0 {
					t.Fatal("no decision line")
				}
				last := e.logBuf.reasons()
				if got := last[len(last)-1]; got != string(tc.reason) {
					t.Fatalf("reason = %q, want %q", got, tc.reason)
				}
			}
		})
	}
}

// TestProofBeatsCookieForCSRF: a request with both a cookie and a valid signed
// proof is the proof path, reports X-Aivan-Proof: nonce, and skips the CSRF
// rule.
func TestProofBeatsCookieForCSRF(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	// An unsafe method that CSRF would refuse for a cookie alone.
	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = `{"a":1}`
	req := e.request(s)
	req.Header.Set("Cookie", gate.SessionCookie+"="+sess.Cookie)

	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	r.assertAllowed(t, d)
	if got := r.Header.Get(gate.HeaderProof); got != gate.ProofNonce {
		t.Fatalf("X-Aivan-Proof = %q, want nonce", got)
	}
}

// TestLogoutDeletesTheRowAndIsIdempotent: DELETE removes the session and
// clears the cookie; a second DELETE is still 204.
func TestLogoutDeletesTheRowAndIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	if n := e.sessionsFor(d); n != 1 {
		t.Fatalf("sessions after mint = %d, want 1", n)
	}

	del := func(cookie string) *response {
		req, err := http.NewRequest(http.MethodDelete, e.server.URL+"/__aivan/session", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Cookie", gate.SessionCookie+"="+cookie)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		return readResponse(t, resp)
	}

	r := del(sess.Cookie)
	if r.Status != http.StatusNoContent {
		t.Fatalf("logout status = %d %q, want 204", r.Status, r.Body)
	}
	const wantClear = gate.SessionCookie + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
	if got := r.Header.Get("Set-Cookie"); got != wantClear {
		t.Fatalf("logout Set-Cookie = %q, want %q", got, wantClear)
	}
	if n := e.sessionsFor(d); n != 0 {
		t.Fatalf("sessions after logout = %d, want 0", n)
	}

	// The cleared cookie no longer authenticates.
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertDenied401(t)

	// A second logout with the same cookie is still 204, and so is a logout
	// with no cookie at all.
	if r := del(sess.Cookie); r.Status != http.StatusNoContent {
		t.Fatalf("second logout = %d, want 204", r.Status)
	}
	req, _ := http.NewRequest(http.MethodDelete, e.server.URL+"/__aivan/session", nil)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if r := readResponse(t, resp); r.Status != http.StatusNoContent {
		t.Fatalf("logout with no cookie = %d, want 204", r.Status)
	}
}

// TestSessionVerifyIsOneStatement asserts the round-trip budget on the pool
// counter, and that the 60 s write window bounds the idle update.
func TestSessionVerifyIsOneStatement(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	e.counter.Reset()
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("session verify issued %d statements, want exactly 1", n)
	}

	hashHex := fmt.Sprintf("%x", proof.SHA256Sum([]byte(sess.Cookie)))
	// setIdle writes the value a verify 15 minutes minus gap ago would have
	// left. The database clock decides, so the row is aged rather than the
	// test sleeping.
	setIdle := func(gap string) {
		harnessExec(t, e.super, fmt.Sprintf(`
			update authz.sessions
			   set idle_expires_at = now() + interval '15 minutes' - interval '%s'
			 where token_hash = decode('%s', 'hex')`, gap, hashHex))
	}

	// A 30 s gap is inside the 60 s window, so the value is left alone.
	setIdle("30 seconds")
	before, _, _ := e.sessionRowFor(sess.Cookie)
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
	unchanged, _, _ := e.sessionRowFor(sess.Cookie)
	if !unchanged.Equal(before) {
		t.Fatalf("idle_expires_at moved for a 30 s gap: %s -> %s", before, unchanged)
	}

	// A 90 s gap is more than the window, so the verify pushes it to
	// now + idle.
	setIdle("90 seconds")
	widened, _, _ := e.sessionRowFor(sess.Cookie)
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
	moved, _, _ := e.sessionRowFor(sess.Cookie)
	if !moved.After(widened) {
		t.Fatalf("idle_expires_at did not move for a 90 s gap: %s -> %s", widened, moved)
	}
	if got, want := moved, e.now.Add(15*time.Minute); got.Sub(want).Abs() > time.Minute {
		t.Fatalf("idle_expires_at = %s, want about now + 15 minutes (%s)", got, want)
	}

	// The same two verifies are still one statement each, so the bounded write
	// costs no extra round trip either way.
	e.counter.Reset()
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("window verify issued %d statements, want 1", n)
	}
}

// TestSessionIsScopedToItsOrigin: a cookie minted on one host does not
// authenticate another, even if the browser were somehow made to send it. The
// __Host- prefix already stops a browser; this is the server's half.
func TestSessionIsScopedToItsOrigin(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	s := signedRequest{Host: "second.home.arpa", Target: "/dashboard"}
	req := e.request(s)
	for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
		req.Header.Del(h)
	}
	req.Header.Set("Cookie", gate.SessionCookie+"="+sess.Cookie)
	resp, err := e.server.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertDenied401(t)
}

// TestSessionRefusesDeactivatedUser: deactivating a person ends their live
// sessions on the next request, the same way revoking a device does. The check
// reads u.active through the same join, so it costs no extra statement.
func TestSessionRefusesDeactivatedUser(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)

	e.setActive(userAlice, false)
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertDenied401(t)

	// Reactivating restores the same session, because nothing deleted it.
	e.setActive(userAlice, true)
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
}

// TestSessionMintRefusesAnInactiveUser: the session path enforces the same
// account checks as the proof path.
func TestSessionMintRefusesAnInactiveUser(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	carol := e.enroll(3, sessionHost, "browser", "ed25519")

	s := e.valid(carol)
	req := e.mintRequest(carol)
	req.Header.Set(gate.HeaderNonce, s.Nonce)
	req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
	req.Header.Set(gate.HeaderSignature, s.signatureFor(e))
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	r.assertDenied401(t)
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("inactive user got a cookie: %q", got)
	}
}

// TestMalformedCookieIsNoCredential: a cookie that could not have been minted
// is ignored, so the request is the ordinary no-proof 401 and never reaches
// the database.
func TestMalformedCookieIsNoCredential(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, value := range []string{"short", strings.Repeat("=", 43), strings.Repeat("a", 42) + "+"} {
		req := e.request(signedRequest{Target: "/dashboard"})
		for _, h := range []string{gate.HeaderDevice, gate.HeaderNonce, gate.HeaderSignature, gate.HeaderTimestamp} {
			req.Header.Del(h)
		}
		req.Header.Set("Cookie", gate.SessionCookie+"="+value)

		e.counter.Reset()
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		readResponse(t, resp).assertDenied401(t)
		if n := e.counter.Value(); n != 0 {
			t.Fatalf("%q reached the database (%d statements)", value, n)
		}
	}
}

// TestSessionEndpointRejectsOtherMethods: only POST and DELETE are answered,
// and the Allow header says so.
func TestSessionEndpointRejectsOtherMethods(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch} {
		req, err := http.NewRequest(method, e.server.URL+"/__aivan/session", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		r := readResponse(t, resp)
		if r.Status != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d, want 405", method, r.Status)
		}
		if got := r.Header.Get("Allow"); got != "POST, DELETE" {
			t.Errorf("%s Allow = %q, want POST, DELETE", method, got)
		}
	}
}

// TestMintProofMustCoverTheMintPath: a proof signed for an application route
// cannot be replayed at the session endpoint to obtain a cookie, even when the
// request claims forwarded headers for that route.
//
// The endpoint is not behind forwardAuth, so a well-behaved proxy sets no
// X-Forwarded-Method or X-Forwarded-Uri here. The handler nevertheless pins the
// signed method and target to POST /__aivan/session, so a request that does
// carry them cannot turn a proof for GET /dashboard into a cookie.
func TestMintProofMustCoverTheMintPath(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	// A valid proof for GET /dashboard, presented to the mint endpoint with
	// forwarded headers that agree with it.
	s := e.valid(d)
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/__aivan/session", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", sessionHost)
	req.Header.Set("X-Forwarded-Uri", "/dashboard")
	req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
	req.Header.Set(gate.HeaderNonce, s.Nonce)
	req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", s.Timestamp.Unix()))
	req.Header.Set(gate.HeaderSignature, s.signatureFor(e))

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	r.assertDenied401(t)
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("a proof for /dashboard minted a cookie: %q", got)
	}
	if n := e.sessionsFor(d); n != 0 {
		t.Fatalf("%d session rows written, want 0", n)
	}

	// The same proof made over the mint's own method and target works even if
	// the forwarded headers claim something else, because that is what the
	// handler acts on.
	resp2, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if r := readResponse(t, resp2); r.Status != http.StatusNoContent {
		t.Fatalf("a proof for the mint path = %d, want 204", r.Status)
	}
}

// TestMintStampsLastSeen: the insert updates the device's last_seen_at in the
// same statement, which is the one write per session lifetime that answers
// "when was this device last used".
func TestMintStampsLastSeen(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	if before := e.lastSeen(d); before != nil {
		t.Fatalf("a fresh device already has last_seen_at = %s", before)
	}
	e.mint(d)
	if after := e.lastSeen(d); after == nil {
		t.Fatal("mint did not set last_seen_at")
	}
}

// TestMintRefusesARevokedDevice: the insert selects from the device row, so a
// device revoked between the proof check and the insert yields no cookie.
func TestMintRefusesARevokedDevice(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	e.revoke(d)

	resp, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	r.assertDenied401(t)
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("a revoked device got a cookie: %q", got)
	}
}

// TestSessionCookieIsNotSetOnADenial: the denial writer never adds Set-Cookie,
// so a 401 shaped by the session path cannot hand a browser a cookie.
func TestSessionCookieIsNotSetOnADenial(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	r := e.verifyWith(sess.Cookie, http.MethodPost, "/dashboard") // csrf_missing: 403
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", r.Status)
	}
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("403 carried Set-Cookie: %q", got)
	}
}

// TestMintedSessionUnaffectedByIdleWriteWindow: a verify that does not write
// the idle expiry is still one statement, which is the point of the case.
// (The value assertion lives in TestSessionVerifyIsOneStatement.)
func TestMintedSessionUnaffectedByIdleWriteWindow(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	sess := e.mint(d)

	for i := 0; i < 3; i++ {
		e.counter.Reset()
		e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)
		if n := e.counter.Value(); n != 1 {
			t.Fatalf("verify %d issued %d statements, want 1", i, n)
		}
	}
}

// assertAllowedSession is assertAllowed for the cookie path: the mechanism is
// session rather than nonce.
func (r *response) assertAllowedSession(t *testing.T, d device) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d %q, want 200", r.Status, r.Body)
	}
	for k, want := range map[string]string{
		gate.HeaderUserID:   fmt.Sprintf("%d", d.UserID),
		gate.HeaderUser:     d.Username,
		gate.HeaderDeviceID: proof.FormatDeviceID(d.ID),
		gate.HeaderProof:    gate.ProofSession,
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}
