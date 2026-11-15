//go:build integration

package gate_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
)

// mintTarget is the path a mint proof must cover, written out so the test does
// not import an unexported constant from the package it is testing through its
// public surface. The handler pins the same value (mintPath in session.go);
// TestMintProofMustCoverTheMintPath is what holds the handler to it.
const mintTarget = "/__aivan/session"

// TestLapsedSessionIsRepairedByAStoredKey is phase 1's round trip as a browser
// performs it: a cookie session that lapsed is repaired by the key the device
// already holds, and the cookie that follows opens a gated route.
//
// The lapse is real: the session row's absolute expiry is moved into the past,
// so /__aivan/verify answers 401 to the cookie the browser sent. The browser's
// next move is the one this phase adds: a nonce, a canonical string over POST
// /__aivan/session, and the four proof headers.
func TestLapsedSessionIsRepairedByAStoredKey(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	// A session that exists and then lapses.
	lapsed := e.mint(d)
	if r := e.verifyWith(lapsed.Cookie, http.MethodGet, "/dashboard"); r.Status != http.StatusOK {
		t.Fatalf("a fresh session = %d, want 200", r.Status)
	}
	e.expireSession(lapsed.Cookie)
	if r := e.verifyWith(lapsed.Cookie, http.MethodGet, "/dashboard"); r.Status != http.StatusUnauthorized {
		t.Fatalf("a lapsed session = %d, want 401", r.Status)
	}

	// The browser's repair: nonce, canonical string, signature, mint.
	resp, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusNoContent {
		t.Fatalf("re-proof = %d %q, want 204", r.Status, r.Body)
	}
	fresh, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("mint Set-Cookie: %v", err)
	}
	if fresh == lapsed.Cookie {
		t.Fatal("the repair reused the lapsed token")
	}

	// The repaired cookie is what opens the gated route, with the identity the
	// device has.
	v := e.verifyWith(fresh, http.MethodGet, "/dashboard")
	if v.Status != http.StatusOK {
		t.Fatalf("repaired session = %d %q, want 200", v.Status, v.Body)
	}
	if got := v.Header.Get(gate.HeaderDeviceID); got != proof.FormatDeviceID(d.ID) {
		t.Errorf("device = %q, want %q", got, proof.FormatDeviceID(d.ID))
	}
	if got := v.Header.Get(gate.HeaderProof); got != gate.ProofSession {
		t.Errorf("proof = %q, want %q", got, gate.ProofSession)
	}

	// And the same repair reaches an admin route for an admin's device: the
	// tier is the device's, and the repair does not change it.
	if a := e.verifyWith(fresh, http.MethodGet, "/admin"); a.Status != http.StatusOK {
		t.Fatalf("repaired admin session = %d, want 200", a.Status)
	}
}

// TestReproofOfARevokedDeviceIsRefused pins the second browser case: a device
// whose key is still in the browser but is revoked gets no cookie. The nonce is
// a real one and the proof is well formed, so the refusal comes from the device
// row, which is the "no longer allowed" case the login page reports.
func TestReproofOfARevokedDeviceIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")
	lapsed := e.mint(d)
	e.expireSession(lapsed.Cookie)
	e.revoke(d)

	resp, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := readResponse(t, resp)
	r.assertDenied401(t)
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("a revoked device minted a cookie: %q", got)
	}
	// The one row is the lapsed session; the refused repair wrote none.
	if n := e.sessionsFor(d); n != 1 {
		t.Fatalf("session rows = %d, want the one lapsed row", n)
	}
}

// TestTheLoginPageIsReachableWithoutASession: the page whose job is to mint a
// session must not require one, and every resource it names must be a path
// this service serves.
//
// The routes are mounted on the package's own test server, which is the same
// mux shape httpx.NewRouterWith builds; httpx's router test is what asserts the
// shipped router mounts them.
func TestTheLoginPageIsReachableWithoutASession(t *testing.T) {
	e := newEnv(t)

	r := e.get(gate.LoginPath)
	if r.Status != http.StatusOK {
		t.Fatalf("login page = %d %q, want 200", r.Status, r.Body)
	}
	if !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html", r.Header.Get("Content-Type"))
	}
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("the login page has no restrictive CSP: %q", r.Header.Get("Content-Security-Policy"))
	}

	for path, want := range map[string]string{
		"/__aivan/login/app.js":       "reproof",
		"/__aivan/login/reproof.js":   "storedDevice",
		"/__aivan/login/canonical.js": "aivan-v1",
	} {
		ar := e.get(path)
		if ar.Status != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, ar.Status)
			continue
		}
		if !strings.Contains(ar.Header.Get("Content-Type"), "text/javascript") {
			t.Errorf("%s Content-Type = %q", path, ar.Header.Get("Content-Type"))
		}
		if !strings.Contains(ar.Body, want) {
			t.Errorf("%s does not contain %q", path, want)
		}
		for _, imp := range importsOf(ar.Body) {
			// A relative specifier resolves against the module's own URL, which
			// is under the login prefix; a bare path does not, and is what the
			// enrollment page's regression test is about.
			if strings.HasPrefix(imp, "./") || strings.HasPrefix(imp, "/__aivan/login/") {
				continue
			}
			t.Errorf("%s imports %q, which is not served under its own prefix", path, imp)
		}
	}

	// A path under the prefix that is not one of the three files is a 404, and
	// a POST is a 405: the page has one method and three files.
	if r := e.get("/__aivan/login/nothing.js"); r.Status != http.StatusNotFound {
		t.Errorf("an unknown login asset = %d, want 404", r.Status)
	}
	post, err := http.NewRequest(http.MethodPost, e.server.URL+gate.LoginPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	presp, err := e.client.Do(post)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := readResponse(t, presp).Status; got != http.StatusMethodNotAllowed {
		t.Errorf("POST %s = %d, want 405", gate.LoginPath, got)
	}
	// HEAD is the page with no body, which a link checker sends.
	head, err := http.NewRequest(http.MethodHead, e.server.URL+gate.LoginPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	hresp, err := e.client.Do(head)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if hr := readResponse(t, hresp); hr.Status != http.StatusOK || hr.Body != "" {
		t.Errorf("HEAD %s = %d with body %q, want 200 and no body", gate.LoginPath, hr.Status, hr.Body)
	}
}

// TestBrowserRoundTripFromA401 is the sequence the page performs, request for
// request: a gated GET with no cookie is refused, the nonce is asked for at the
// endpoint, the mint is signed over the nonce and POST /__aivan/session, and
// the cookie that comes back opens the same gated route.
//
// TestLapsedSessionIsRepairedByAStoredKey mints a nonce straight into the
// table; this one goes through the endpoint the page actually calls, which is
// the only difference that matters between the two.
func TestBrowserRoundTripFromA401(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, sessionHost, "browser", "ed25519")

	// 1. The gated route, with no cookie and no proof.
	if r := e.verifyWith("", http.MethodGet, "/dashboard"); r.Status != http.StatusUnauthorized {
		t.Fatalf("no cookie = %d, want 401", r.Status)
	}

	// 2. The nonce, at the endpoint, for the device id the record holds.
	nonce := e.nonceViaEndpoint(d)
	if nonce == "" {
		t.Fatal("the nonce endpoint answered no nonce")
	}

	// 3. The canonical string, as the browser builds it, and the signature.
	// The timestamp is read after the nonce arrived, which is the order the
	// page does it in and the order the gate requires: a timestamp before the
	// nonce was issued is a denial.
	ts := e.now.Add(time.Second).Unix()
	msg := proof.Canonical(proof.Request{
		Method:     http.MethodPost,
		Scheme:     "https",
		Host:       testHost,
		Target:     mintTarget,
		BodySHA256: proof.EmptyBodySHA256,
		Nonce:      nonce,
		Timestamp:  fmt.Sprintf("%d", ts),
	})

	// 4. The mint.
	req, err := http.NewRequest(http.MethodPost, e.server.URL+mintTarget, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	req.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
	req.Header.Set(gate.HeaderNonce, nonce)
	req.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(gate.HeaderSignature, base64.RawURLEncoding.EncodeToString(d.sign(msg)))

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusNoContent {
		t.Fatalf("mint = %d %q, want 204", r.Status, r.Body)
	}
	cookie, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("mint Set-Cookie: %v", err)
	}

	// 5. The same gated route, with the cookie the mint set.
	if v := e.verifyWith(cookie, http.MethodGet, "/dashboard"); v.Status != http.StatusOK {
		t.Fatalf("the minted cookie = %d %q, want 200", v.Status, v.Body)
	}

	// The nonce was spent: the same proof cannot mint a second cookie, which
	// is what stops a captured mint request from being replayed.
	again, err := http.NewRequest(http.MethodPost, e.server.URL+mintTarget, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	again.Header.Set("X-Forwarded-Proto", "https")
	again.Header.Set("X-Forwarded-Host", testHost)
	again.Header.Set(gate.HeaderDevice, proof.FormatDeviceID(d.ID))
	again.Header.Set(gate.HeaderNonce, nonce)
	again.Header.Set(gate.HeaderTimestamp, fmt.Sprintf("%d", ts))
	again.Header.Set(gate.HeaderSignature, base64.RawURLEncoding.EncodeToString(d.sign(msg)))
	aresp, err := e.client.Do(again)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	ar := readResponse(t, aresp)
	ar.assertDenied401(t)
	if got := ar.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("a replayed mint set a cookie: %q", got)
	}
}

// TestLoginCanonicalConstantsMatch is the anti-drift check for the login page's
// canonical builder. The page signs for POST /__aivan/session, so the values
// that decide whether a signature can ever match are the version line, the mint
// path and the empty-body digest. Asserting them against the JavaScript source
// makes a change to one side fail a test rather than a user's sign-in.
func TestLoginCanonicalConstantsMatch(t *testing.T) {
	src := string(gate.EmbeddedPage().LoginCanonical)

	for _, want := range []struct{ what, line string }{
		{"version", "export const REQUEST_VERSION = '" + proof.Version + "';"},
		{"mint path", "export const MINT_PATH = '" + mintTarget + "';"},
		{"empty body digest", "'" + proof.EmptyBodySHA256 + "'"},
		{"host line", "`${r.scheme}://${r.host}`"},
	} {
		if !strings.Contains(src, want.line) {
			t.Errorf("canonical.js does not declare the Go %s (%q)", want.what, want.line)
		}
	}
}

// TestLoginCanonicalAgreesWithGo runs the browser's requestCanonical against
// proof.Canonical on mint-shaped requests, under node when one is on PATH (or
// named by AIVAN_TEST_NODE). The page's only source of truth is
// internal/proof/canonical.go, and this is the test that notices when the two
// have parted.
func TestLoginCanonicalAgreesWithGo(t *testing.T) {
	node, err := nodeBinary()
	if err != nil {
		t.Skipf("no node: %v; the constant check covers the drift this test would catch in full", err)
	}

	cases := []map[string]string{
		{"method": "POST", "scheme": "https", "host": "aivan-hud.home.arpa",
			"target": mintTarget, "bodySha256": proof.EmptyBodySHA256,
			"nonce": "kZ3b1sVn0m6pQ8rT", "timestamp": "1760000000"},
		{"method": "POST", "scheme": "https", "host": "192.168.1.10",
			"target": mintTarget, "bodySha256": proof.EmptyBodySHA256,
			"nonce": "AAECAwQFBgcICQoLDA0ODw", "timestamp": "1"},
	}

	// The builder is the module's own source with the export lines kept, so
	// this reads the bytes the page loads rather than a copy in the test.
	script := string(gate.EmbeddedPage().LoginCanonical) + `
const r = JSON.parse(process.env.AIVAN_MINT_REQUEST);
process.stdout.write(requestCanonical(r));`

	for _, tc := range cases {
		blob, err := json.Marshal(tc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		cmd := exec.Command(node, "--input-type=module", "-e", script)
		cmd.Env = append(os.Environ(), "AIVAN_MINT_REQUEST="+string(blob))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("node: %v\n%s", err, out)
		}
		want := proof.Canonical(proof.Request{
			Method: tc["method"], Scheme: tc["scheme"], Host: tc["host"],
			Target: tc["target"], BodySHA256: tc["bodySha256"],
			Nonce: tc["nonce"], Timestamp: tc["timestamp"],
		})
		if string(out) != want {
			t.Fatalf("the browser builder and proof.Canonical disagree\nbrowser: %q\ngo:      %q", out, want)
		}
	}
}

func importsOf(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "import ") {
			continue
		}
		i := strings.Index(line, "from '")
		if i < 0 {
			continue
		}
		rest := line[i+len("from '"):]
		if j := strings.Index(rest, "'"); j >= 0 {
			out = append(out, rest[:j])
		}
	}
	return out
}

// nodeBinary is the JavaScript runtime the agreement test runs under. A
// desktop checkout usually has none on PATH; AIVAN_TEST_NODE names one, which
// is how the test is run by hand and in a container that ships Playwright.
func nodeBinary() (string, error) {
	if v := os.Getenv("AIVAN_TEST_NODE"); v != "" {
		return v, nil
	}
	return exec.LookPath("node")
}
