//go:build integration

package gate_test

// The two behaviours component 4 of doc/spec-authorization.md §8 needed from the
// gate, pinned here rather than in aivan-hud's cucumber suite, because the
// application's `Local` verifier has no subject check and would pass a scenario
// the installed gate refuses (doc/plan-gate-device-kinds.md:317-326).
//
//   1. A device signature over bytes that name no approval is verifiable, and is
//      the only thing a public `GET /approvals/pending` can be admitted on.
//   2. `self_or_admin` verifies for a device that is not the approval's subject,
//      so an admin's decision reaches the application; `subject` still does not,
//      which is invariant 7 and the reason the column is read rather than the
//      check dropped.
//
// The harness is pentest_h_integration_test.go's `hEnv`, because it is the one
// that builds the gate's production router.

import (
	"context"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
)

// approvalWith is `h.approval` with the requirement as a parameter. The existing
// helper hard-codes `subject`, which is the value this file needs to contrast.
func (h *hEnv) approvalWith(serviceID string, subject int64, hash []byte, requirement string) string {
	h.t.Helper()
	var id string
	if err := h.admin.QueryRow(context.Background(), `
insert into authz.approvals
  (request_id, service_id, subject_user_id, resource, permissions, request_hash,
   request_raw, request_body, approver_requirement, status)
values (gen_random_uuid(), $1, $2, 'hermes', array['read'], $3,
        convert_to('{}', 'UTF8'), '{}'::jsonb, $4, 'pending')
returning id::text`, serviceID, subject, hash, requirement).Scan(&id); err != nil {
		h.t.Fatalf("insert approval: %v", err)
	}
	return id
}

// TestDeviceReadPurposeVerifiesWithoutAnApproval is the first half. The bytes are
// aivan-hud's `Approvals.device_read_canonical`: version, purpose, device, time.
// They name no approval id because there is none, and before
// `PurposeDevice` the handler refused every one of them at the shape check.
func TestDeviceReadPurposeVerifiesWithoutAnApproval(t *testing.T) {
	h := newHEnv(t)

	dev := h.enroll(userAlice, testHost, "phone", "ed25519")
	devID := proof.FormatDeviceID(dev.ID)
	body := "aivan-approval-request-v2\npending\n" + devID + "\n2026-11-17T18:00:00Z"

	claims := h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeDevice, "device": devID,
		"body": b64(body), "sig": b64Bytes(dev.sign(body)),
	}))
	h.assertClaims(claims, "device", userAlice, devID)
	claimsBody := claims.Body

	// The claims are the same three keys a decision yields, and nothing else: a
	// device read must not become a way to learn a role or a rank.
	for _, word := range []string{"role", "rank", "level", "admin", "subject"} {
		if strings.Contains(claimsBody, word) {
			t.Errorf("claims carry %q, which is not a claim this purpose may make: %q", word, claimsBody)
		}
	}
}

// TestDeviceReadPurposeRefusesTheApprovalShape is the separation between the two
// device purposes. A signature over a read must not be accepted as a decision,
// which is what the shape check buys: `approval` requires an approval id and
// `device` refuses one.
func TestDeviceReadPurposeRefusesTheApprovalShape(t *testing.T) {
	h := newHEnv(t)

	dev := h.enroll(userAlice, testHost, "phone", "ed25519")
	svc := h.enroll(userAlice, "service.example", "browser", "ed25519")
	svcID := h.service("device-read-shape", svc)
	apprID := h.approvalWith(svcID, userAlice, hashFor("shape"), "subject")
	devID := proof.FormatDeviceID(dev.ID)

	decision := decisionCanonical(apprID, hashFor("shape"), "approve", devID, "3600", "2026-11-17T18:00:00Z")

	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeDevice, "device": devID, "approval": apprID,
		"body": b64(decision), "sig": b64Bytes(dev.sign(decision)),
	})), "bad_request")

	// A device purpose naming a service is refused too, for the same reason.
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeDevice, "device": devID, "service": svcID,
		"body": b64(decision), "sig": b64Bytes(dev.sign(decision)),
	})), "bad_request")
}

// TestSelfOrAdminVerifiesForANonSubjectDevice is the second half: an admin's
// phone may verify a decision over a request whose subject is someone else, when
// the row says `self_or_admin`. The application's `may_decide?` is then the only
// check that the decider is an admin, and `spec §9` invariant 7 still holds
// because `subject` is refused below.
func TestSelfOrAdminVerifiesForANonSubjectDevice(t *testing.T) {
	h := newHEnv(t)

	alice := h.enroll(userAlice, testHost, "phone", "ed25519")
	bob := h.enroll(userBob, "aivan-pt.home.arpa", "phone", "ed25519")
	svc := h.enroll(userAlice, "service.example", "browser", "ed25519")
	svcID := h.service("self-or-admin", svc)
	aliceID := proof.FormatDeviceID(alice.ID)
	bobID := proof.FormatDeviceID(bob.ID)

	hash := hashFor("self-or-admin")

	// `subject`: bob's device over alice's request is still refused. This is the
	// check the component must not weaken, and it is the same refusal PH-4 pins.
	subjectID := h.approvalWith(svcID, userAlice, hash, "subject")
	body := decisionCanonical(subjectID, hash, "approve", bobID, "3600", "2026-11-17T18:00:00Z")
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeApproval, "device": bobID, "approval": subjectID,
		"body": b64(body), "sig": b64Bytes(bob.sign(body)),
	})), "role_insufficient")

	// `admin`: still refused for a non-subject device. The gate reads the column
	// and widens only for `self_or_admin`; who may decide an admin request stays
	// the application's rule, and the refusal here is the same one `subject`
	// gets.
	adminID := h.approvalWith(svcID, userAlice, hash, "admin")
	adminBody := decisionCanonical(adminID, hash, "approve", bobID, "3600", "2026-11-17T18:00:00Z")
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeApproval, "device": bobID, "approval": adminID,
		"body": b64(adminBody), "sig": b64Bytes(bob.sign(adminBody)),
	})), "role_insufficient")

	// `self_or_admin`: the arm component 4 added. It verifies, and the request
	// hash check still runs, so a wrong third line is refused rather than
	// waved through with the subject rule.
	selfOrAdminID := h.approvalWith(svcID, userAlice, hash, "self_or_admin")
	selfOrAdminBody := decisionCanonical(selfOrAdminID, hash, "approve", bobID, "3600", "2026-11-17T18:00:00Z")
	h.assertClaims(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeApproval, "device": bobID, "approval": selfOrAdminID,
		"body": b64(selfOrAdminBody), "sig": b64Bytes(bob.sign(selfOrAdminBody)),
	})), "device", userBob, bobID)

	crossed := decisionCanonical(selfOrAdminID, hashFor("other"), "approve", bobID, "3600", "2026-11-17T18:00:00Z")
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeApproval, "device": bobID, "approval": selfOrAdminID,
		"body": b64(crossed), "sig": b64Bytes(bob.sign(crossed)),
	})), "bad_signature")

	// The subject's own device still verifies its own `self_or_admin` request,
	// which is the arm that already worked.
	ownBody := decisionCanonical(selfOrAdminID, hash, "approve", aliceID, "3600", "2026-11-17T18:00:00Z")
	h.assertClaims(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeApproval, "device": aliceID, "approval": selfOrAdminID,
		"body": b64(ownBody), "sig": b64Bytes(alice.sign(ownBody)),
	})), "device", userAlice, aliceID)
}

// TestDeviceReadPurposeRefusesAnUnapprovedDevice pins that the third purpose
// inherits the liveness rule rather than bypassing it: a revoked or pending
// device signs nothing, whichever purpose it asks for. Without this the new
// purpose would be a way around the check the other two make.
func TestDeviceReadPurposeRefusesAnUnapprovedDevice(t *testing.T) {
	h := newHEnv(t)

	dev := h.enroll(userAlice, testHost, "phone", "ed25519")
	devID := proof.FormatDeviceID(dev.ID)
	body := "aivan-approval-request-v2\npending\n" + devID + "\n2026-11-17T18:00:00Z"

	// Revoked: both columns move together, or the biconditional CHECK refuses the
	// write. The console's revoke is the product path; this is the same
	// transition.
	if _, err := h.admin.Exec(context.Background(),
		`update authz.devices set state = 'revoked', revoked_at = now() where id = $1`, dev.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	h.assertRefused(h.postVerify(payload(map[string]string{
		"purpose": gate.PurposeDevice, "device": devID,
		"body": b64(body), "sig": b64Bytes(dev.sign(body)),
	})), "device_revoked")

	// The body is unchanged and the signature is still valid; only the row's
	// state moved, which is what makes this the liveness check and not the
	// signature.
	if !strings.Contains(h.logBuf.String(), "device_revoked") {
		t.Fatal("the refusal was not logged as device_revoked")
	}
}
