//go:build integration

package gate_test

// Component 2 of doc/spec-authorization.md §8: the pending device state, the
// widened kinds, and the anonymous-at-a-device rule.
//
// Each test here is a guard-removal row from doc/plan-gate-device-kinds.md §7.
// The table names the test that fails when the mechanism goes, so every test
// below is named the way the table names it and exercises exactly that
// mechanism rather than the class around it.

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
)

// TestPendingDeviceProofIsRefused: a signed proof over a pending device's own
// key verifies and is still refused, with `device_pending` in the decision log
// rather than `device_revoked` or `bad_signature`. Without the state branch the
// pending device would authenticate on the proof path, which is the one nobody
// would think to test after writing a pending row.
func TestPendingDeviceProofIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	d := e.enroll(userAlice, testHost, "phone", "ed25519")
	e.setState(d, "pending")

	// The proof is correct in every other way: a live nonce, the right key, the
	// right origin. Only the row's state stands between it and a 200.
	e.do(e.valid(d)).assertDenied401(t)
	if got := e.logBuf.reasons(); !contains(got, string(gate.ReasonDevicePending)) {
		t.Fatalf("decision reasons = %v, want one %q", got, gate.ReasonDevicePending)
	}

	// And the same proof succeeds once the device is live, so the refusal was
	// the state and not something else about the fixture.
	e.setState(d, "live")
	if got := e.do(e.valid(d)); got.Status != http.StatusOK {
		t.Fatalf("a live device = %d %q, want 200", got.Status, got.Body)
	}
}

// TestPendingDeviceCannotMint: SessionMintSQL's `state = 'live'` is the whole of
// this refusal. Remove it from the statement and a pending device gets a cookie,
// which is why the predicate lives in SQL rather than only in the Go check that
// reads the proof.
func TestPendingDeviceCannotMint(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	d := e.enroll(userAlice, testHost, "browser", "ed25519")
	e.setState(d, "pending")

	resp, err := e.client.Do(e.mintRequest(d))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := readResponse(t, resp)
	r.assertDenied401(t)
	if got := r.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("a pending device minted a cookie: %q", got)
	}
	if n := e.sessionsFor(d); n != 0 {
		t.Fatalf("a pending device has %d session rows", n)
	}

	// And the statement itself, not only the handler. The handler refuses the
	// proof before this statement is reached, so the handler test would pass
	// with the predicate gone; this is what pins `state = 'live'` in the SQL.
	// It is the check-then-act guard: a device that goes pending between the
	// proof check and the insert must still not get a row.
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatalf("token: %v", err)
	}
	hash := proof.SHA256Sum(token[:])
	interval := func(d time.Duration) pgtype.Interval {
		return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
	}
	if _, err := e.pool.Exec(context.Background(), store.StmtSessionMint, hash[:],
		pgtype.UUID{Bytes: d.ID, Valid: true}, testHost,
		interval(15*time.Minute), interval(8*time.Hour)); err != nil {
		t.Fatalf("run the mint statement: %v", err)
	}
	if n := e.sessionsFor(d); n != 0 {
		t.Fatalf("the mint statement wrote %d session rows for a pending device", n)
	}
}

// TestPendingDeviceCannotReadASession: a session row minted while the device was
// live stops authenticating the moment the row is not live, on that very
// request (S5's shape, extended to the new state).
func TestPendingDeviceCannotReadASession(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	d := e.enroll(userAlice, testHost, "browser", "ed25519")
	sess := e.mint(d)
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertAllowedSession(t, d)

	// The row goes back to pending with the session untouched. No code path
	// produces this; an operator repairing a row can.
	e.setState(d, "pending")
	e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard").assertDenied401(t)
	if got := e.logBuf.reasons(); !contains(got, string(gate.ReasonDevicePending)) {
		t.Fatalf("decision reasons = %v, want one %q", got, gate.ReasonDevicePending)
	}
}

// TestPendingDeviceCannotSignAnApproval: a pending device must not spend a
// decision, so DeviceKeySQL selects `state` and the verifier refuses a non-live
// row before it checks the signature. Remove `state` from that statement and the
// pending device's signature verifies.
func TestPendingDeviceCannotSignAnApproval(t *testing.T) {
	h := newHEnv(t)
	d := h.enroll(userAlice, testHost, "phone", "ed25519")
	approvalID, hash := h.seedApproval(userAlice)
	h.setState(d, "pending")

	body := decisionCanonical(approvalID, hash, "approve", proof.FormatDeviceID(d.ID), "3600", "")
	signed := payload(map[string]string{
		"purpose":  "approval",
		"device":   proof.FormatDeviceID(d.ID),
		"approval": approvalID,
		"body":     b64Bytes([]byte(body)),
		"sig":      b64Bytes(d.sign(body)),
	})
	h.assertRefused(h.postVerify(signed), string(gate.ReasonDevicePending))

	// The identical signature verifies once the device is live.
	h.setState(d, "live")
	h.assertClaims(h.postVerify(signed), "device", userAlice, proof.FormatDeviceID(d.ID))
}

// TestAPanelCodeClaims: the schema admits a panel and the claim accepts it, so a
// panel is a device rather than a schema value nothing produces. The device a
// claim creates is live, which is what S11 means by "a claim produces a live
// device".
func TestAPanelCodeClaims(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, kind := range []string{"panel", "tv"} {
		code := e.mintPending(userAlice, testHost, kind, 15*time.Minute)
		req := claimFor(t, code, newClaimant(t, "ed25519"))
		req.Kind = kind
		r := e.claim(req)
		if r.Status != http.StatusCreated {
			t.Fatalf("%s claim = %d %q, want 201", kind, r.Status, r.Body)
		}
		if got := r.Header.Get(gate.HeaderDeviceKind); got != kind {
			t.Errorf("device kind = %q, want %q", got, kind)
		}

		deviceID, err := proof.ParseDeviceID(r.Header.Get(gate.HeaderDeviceID))
		if err != nil {
			t.Fatalf("device id: %v", err)
		}
		_, _, recorded, state, _ := e.deviceRowWithState(deviceID)
		if recorded != kind || state != "live" {
			t.Fatalf("device = %s/%s, want %s/live", recorded, state, kind)
		}
	}
}

// TestPanelProofIsAnonymousAtTheDevice is step 4's first guard. A panel has no
// occupant, so its proof reaches the application as a device and not as a
// person: the device headers are present and the person's are *absent*.
//
// Absence rather than "0" is the assertion, because a header reading "0" is a
// value every application would key a foreign key on. Remove the guard in
// `allow` and this test reads "0" and fails.
func TestPanelProofIsAnonymousAtTheDevice(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, kind := range []string{"panel", "tv"} {
		d := e.enroll(userAlice, testHost, kind, "ed25519")
		r := e.do(e.valid(d))
		if r.Status != http.StatusOK {
			t.Fatalf("%s proof = %d %q, want 200", kind, r.Status, r.Body)
		}
		if got := r.Header.Get(gate.HeaderDeviceKind); got != kind {
			t.Errorf("X-Aivan-Device-Kind = %q, want %q", got, kind)
		}
		if got := r.Header.Get(gate.HeaderDeviceID); got != proof.FormatDeviceID(d.ID) {
			t.Errorf("X-Aivan-Device-Id = %q, want the %s's id", got, kind)
		}
		for _, h := range []string{gate.HeaderUserID, gate.HeaderUser, gate.HeaderRoles} {
			if got := r.Header.Get(h); got != "" {
				t.Errorf("a %s proof carried %s = %q; the header must be absent", kind, h, got)
			}
		}
	}
}

// TestBrowserProofStillCarriesItsUser is the other half: a branch inverted would
// make every person anonymous, and this is what catches it.
func TestBrowserProofStillCarriesItsUser(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	for _, kind := range []string{"browser", "phone", "tablet"} {
		d := e.enroll(userAlice, testHost, kind, "ed25519")
		r := e.do(e.valid(d))
		r.assertAllowed(t, d)
		if got := r.Header.Get(gate.HeaderRoles); got != "admin,free" {
			t.Errorf("%s roles = %q, want admin,free", kind, got)
		}
	}
}

// TestPanelSessionIsAlsoAnonymousAtTheDevice: the two identity-construction
// sites share one helper, so the cookie path cannot disagree with the proof path
// about what a panel is.
func TestPanelSessionIsAlsoAnonymousAtTheDevice(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	d := e.enroll(userAlice, testHost, "panel", "ed25519")
	sess := e.mint(d)
	r := e.verifyWith(sess.Cookie, http.MethodGet, "/dashboard")
	if r.Status != http.StatusOK {
		t.Fatalf("panel session = %d %q, want 200", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "panel" {
		t.Errorf("X-Aivan-Device-Kind = %q, want panel", got)
	}
	for _, h := range []string{gate.HeaderUserID, gate.HeaderUser, gate.HeaderRoles} {
		if got := r.Header.Get(h); got != "" {
			t.Errorf("a panel's session carried %s = %q", h, got)
		}
	}
}

// TestBrowserIsRefusedAConfidentialRoute is the kind comparison's guard. It runs
// against a gate whose policy names a confidential route, so the mechanism is
// exercised through the handler rather than only in CheckClass's unit test.
func TestBrowserIsRefusedAConfidentialRoute(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	// A second server on the same database whose only difference is one
	// confidential route, so the shipped policy is not what is under test.
	confidential := e.serverWithTable(t, confidentialTable(t))

	phone := e.enroll(userAlice, testHost, "phone", "ed25519")
	browser := e.enroll(userAlice, testHost, "browser", "ed25519")

	vault := func(d device) signedRequest {
		s := e.valid(d)
		s.Target = "/vault"
		return s
	}

	if r := e.doOn(confidential, vault(phone)); r.Status != http.StatusOK {
		t.Fatalf("a phone on a phone-only route = %d %q, want 200", r.Status, r.Body)
	}
	r := e.doOn(confidential, vault(browser))
	if r.Status != http.StatusForbidden {
		t.Fatalf("a browser on a phone-only route = %d %q, want 403", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderUserID); got != "" {
		t.Errorf("a refusal carried X-Aivan-User-Id %q", got)
	}
	if got := e.lastDecisionReason(); got != string(gate.ReasonDeviceKindInsufficient) {
		t.Errorf("reason = %q, want %q", got, gate.ReasonDeviceKindInsufficient)
	}

	// The same browser reaches an ordinary route, so the refusal is the route's
	// kinds and not the device.
	ordinary := e.valid(browser)
	ordinary.Target = "/dashboard"
	if r := e.doOn(confidential, ordinary); r.Status != http.StatusOK {
		t.Fatalf("a browser on an authenticated route = %d %q, want 200", r.Status, r.Body)
	}
}

// TestAnAdminDecidingForAnotherSubjectIsRefusedByTheGate pins the gate behaviour
// doc/plan-gate-device-kinds.md step 5 leaves alone. A device whose user is not
// the approval's subject is refused *before* the application is asked, so
// `self_or_admin` works in cucumber (`Local` has no such check) and not yet on
// an install. Component 4 redefines the decider relationship; this component
// records the limitation rather than relaxing it, because that check is what
// makes a stolen phone's signature useless against someone else's approval.
func TestAnAdminDecidingForAnotherSubjectIsRefusedByTheGate(t *testing.T) {
	h := newHEnv(t)

	// alice is the admin; the approval is for bob. Alice's own phone signs it.
	admin := h.enroll(userAlice, testHost, "phone", "ed25519")
	approvalID, hash := h.seedApproval(userBob)

	body := decisionCanonical(approvalID, hash, "approve", proof.FormatDeviceID(admin.ID), "3600", "")
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose":  "approval",
		"device":   proof.FormatDeviceID(admin.ID),
		"approval": approvalID,
		"body":     b64Bytes([]byte(body)),
		"sig":      b64Bytes(admin.sign(body)),
	})), string(gate.ReasonRoleInsufficient))

	// Bob's own phone is accepted, so the refusal is the decider and not the
	// fixture.
	subject := h.enroll(userBob, testHost, "phone", "ed25519")
	own := decisionCanonical(approvalID, hash, "decline", proof.FormatDeviceID(subject.ID), "", "")
	h.assertClaims(h.postVerify(payload(map[string]string{
		"purpose":  "approval",
		"device":   proof.FormatDeviceID(subject.ID),
		"approval": approvalID,
		"body":     b64Bytes([]byte(own)),
		"sig":      b64Bytes(subject.sign(own)),
	})), "device", userBob, proof.FormatDeviceID(subject.ID))
}

// TestRevokeSetsState is the biconditional's guard from the function side:
// authz.revoke_device moves both columns, so the CHECK accepts the row. Drop
// `state = 'revoked'` from the function and its UPDATE is rejected instead.
func TestRevokeSetsState(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	d := e.enroll(userAlice, testHost, "browser", "ed25519")
	if _, err := console.Revoke(context.Background(), e.admin, proof.FormatDeviceID(d.ID), "state-test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, _, _, state, revoked := e.deviceRowWithState(d.ID)
	if state != "revoked" {
		t.Fatalf("state = %q after revoke, want revoked", state)
	}
	if revoked == nil {
		t.Fatal("revoked_at is null after revoke")
	}
}

// ---- helpers this file adds --------------------------------------------

// lastDecisionReason is the reason code of the most recent decision. The other
// helper of this name takes an *hEnv, and the confidential-route test uses the
// plain environment.
func (e *env) lastDecisionReason() string {
	e.t.Helper()
	reasons := e.logBuf.reasons()
	if len(reasons) == 0 {
		e.t.Fatal("no decision was logged")
	}
	return reasons[len(reasons)-1]
}

// deviceRowWithState reads a device row's owner, origin, kind, state and
// revoked_at through the credential the gate does not hold.
func (e *env) deviceRowWithState(id [16]byte) (userID int64, origin, kind, state string, revoked *string) {
	e.t.Helper()
	var revokedAt *string
	if err := e.admin.QueryRow(context.Background(), `
select user_id, origin, kind, state, revoked_at::text
  from authz.devices where id = $1`, proof.FormatDeviceID(id)).
		Scan(&userID, &origin, &kind, &state, &revokedAt); err != nil {
		e.t.Fatalf("read device row: %v", err)
	}
	return userID, origin, kind, state, revokedAt
}

// confidentialTable is the install's table plus one confidential route.
func confidentialTable(t testing.TB) *policy.Table {
	t.Helper()
	tbl, err := policy.New(map[string]policy.Host{
		testHost: {
			Routes: []policy.Route{
				{Prefix: policy.EnrollmentPrefix, Class: policy.ClassEnrollment},
				{Prefix: "/", Class: policy.ClassAuthenticated},
				{Prefix: "/admin", Class: policy.ClassAdmin},
				{Prefix: "/vault", Class: policy.ClassConfidential, Kinds: []string{"phone"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return tbl
}

// seedApproval inserts one pending approval for subject and returns its id and
// stored request hash, so a decision signature can name both.
func (h *hEnv) seedApproval(subject int64) (string, []byte) {
	h.t.Helper()
	svc := h.enroll(userAlice, "service.example", "browser", "ed25519")
	serviceID := h.service(fmt.Sprintf("state-test-%d", subject), svc)
	hash := hashFor(fmt.Sprintf("state-test-%d", subject))
	return h.approval(serviceID, subject, hash, "pending", nil), hash
}
