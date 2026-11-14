//go:build integration

package gate_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
)

// bodyOf returns exactly n bytes of a repeating printable payload.
func bodyOf(n int) string {
	const chunk = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	b.Grow(n)
	for b.Len() < n {
		b.WriteString(chunk)
	}
	return b.String()[:n]
}

// TestS18BodyAtTheLimitIsVerifiedWhole is G2's "not truncated" row, asserted
// where it can be asserted without an application: a body of exactly the limit
// minus one is read in full and its digest matches the one the client signed.
// A truncating reader would produce a different digest and the signature would
// fail, so the 200 is the proof.
func TestS18BodyAtTheLimitIsVerifiedWhole(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// The env's MaxBody is 65536; one below it is the largest body that must
	// succeed.
	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = bodyOf(65535)

	r := e.do(s)
	if r.Status != http.StatusOK {
		t.Fatalf("body of %d bytes = %d %q, want 200", len(s.Body), r.Status, r.Body)
	}
	r.assertAllowed(t, d)
}

// TestS18BodyOverTheLimitIs413 is the other row: one byte more is refused with
// the gate's own 413, and the reason is body_too_large rather than a proof
// failure.
func TestS18BodyOverTheLimitIs413(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = bodyOf(65537)

	r := e.do(s)
	if r.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("body of %d bytes = %d %q, want 413", len(s.Body), r.Status, r.Body)
	}
	if got := e.logBuf.reasons(); len(got) == 0 || got[len(got)-1] != string(gate.ReasonBodyTooLarge) {
		t.Errorf("decision reasons = %v, want the last to be %q", got, gate.ReasonBodyTooLarge)
	}
}

// TestS18BodyOverTheLimitOnEveryMethod: the limit is a property of the request,
// not of the method. A GET with a body is hashed as the empty body by design
// (C7), so it is not refused; every method whose body is hashed is.
func TestS18BodyOverTheLimitOnEveryMethod(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			s := e.valid(d)
			s.Method = method
			s.Body = bodyOf(65537)
			if r := e.do(s); r.Status != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s with %d bytes = %d, want 413", method, len(s.Body), r.Status)
			}
		})
	}
}

// TestBodyLimitComesFromConfig: the gate refuses a body above whatever it was
// configured with, so the operator's AIVAN_MAX_BODY is the number in force.
func TestBodyLimitComesFromConfig(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	small := e.serverAtBodyLimit(t, 1024)

	// Under the limit: allowed, with a signature over the real body.
	s := signedRequest{Device: d, Timestamp: e.now,
		Method: http.MethodPost, Body: bodyOf(1024)}
	s.Nonce = e.nonceAt(d, -time.Hour, time.Hour)
	if r := small.do(s); r.Status != http.StatusOK {
		t.Fatalf("1024 bytes against a 1024 limit = %d %q, want 200", r.Status, r.Body)
	}

	s = signedRequest{Device: d, Timestamp: e.now,
		Method: http.MethodPost, Body: bodyOf(1025)}
	s.Nonce = e.nonceAt(d, -time.Hour, time.Hour)
	if r := small.do(s); r.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("1025 bytes against a 1024 limit = %d %q, want 413", r.Status, r.Body)
	}
}

// errorBody is the raw response body of the 413, which the phase file leaves
// unspecified. It is logged so the runbook can quote it.
func TestTooLargeBodyHasNoIdentityHeaders(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.valid(d)
	s.Method = http.MethodPost
	s.Body = bodyOf(70000)
	r := e.do(s)
	if r.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", r.Status)
	}
	for _, h := range []string{gate.HeaderUserID, gate.HeaderUser, gate.HeaderRoles,
		gate.HeaderDeviceID, gate.HeaderDeviceKind, gate.HeaderProof} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("413 carried identity header %s: %q", h, v)
		}
	}
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	t.Logf("413 body = %q", fmt.Sprintf("%q", r.Body))
}
