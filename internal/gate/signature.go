package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chris/aivan-authz/internal/audit"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/reqid"
	"github.com/chris/aivan-authz/internal/store"
)

// VerifySignaturePath is the one surface this service grew for approvals. It
// resolves a key, checks that the key is live, and verifies a signature. It
// returns claims and never authority: the application decides what a valid
// signature is worth (doc/schema-ownership.md §8.2).
const VerifySignaturePath = "/__aivan/verify-signature"

// The body is a signature and an id. Anything larger is not a request this
// endpoint understands; the limit is small on purpose because the endpoint is
// reachable without a session.
const verifySignatureBodyLimit = 4096

// The three purposes a caller can ask about. A request is a service's, an
// approval is a device's over an approval, and a device read is a device's over
// bytes that name no approval; none can be spent as another.
//
// **PurposeDevice is the third, and it exists because a phone has no session.**
// The pending list, the bounds and one approval are read from outside the house,
// where a home cookie cannot follow, so the device signature is the only
// credential. Before this purpose the gate refused every device signature that
// named no approval (`doc/plan-ask-and-grant.md` §3.5), which made a public
// `/approvals/pending` unverifiable.
//
// It grants nothing. It answers "this device signed these bytes", which is what
// the signature already proves, and the application decides what that is worth —
// the same split every purpose here keeps (doc/schema-ownership.md §8.2).
const (
	PurposeRequest  = "request"
	PurposeApproval = "approval"
	PurposeDevice   = "device"
)

// verifySignatureRequest is the whole request shape.
//
// Device and Service are pointers so "absent" and "empty" are different: a
// caller that names neither is malformed rather than a lookup for the empty id.
type verifySignatureRequest struct {
	Purpose  string  `json:"purpose"`
	Body     string  `json:"body"`
	Sig      string  `json:"sig"`
	Device   *string `json:"device,omitempty"`
	Service  *string `json:"service,omitempty"`
	Approval *string `json:"approval,omitempty"`
}

// verifySignatureResponse is the claims a caller gets. It is deliberately
// narrow: which principal signed, and the identity that key belongs to. No
// roles, no permissions, no approval status.
type verifySignatureResponse struct {
	Kind      string `json:"kind"`
	UserID    int64  `json:"user_id,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	ServiceID string `json:"service_id,omitempty"`
}

// VerifySignature verifies a signature over caller-supplied bytes against a
// key this service holds a read on.
//
// It is a POST because the bytes can be long. It is not on the forwardAuth
// path: it is called by aivan-hud, over the cluster network, and never by a
// browser.
//
// Every refusal is a constant 401 with one body, for the same reason the proof
// path's is (S14): a caller must not be able to tell "no such device" from
// "revoked" from "bad signature" by status or body.
func (g *Gate) VerifySignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	req, err := readVerifySignatureRequest(r)
	if err != nil {
		g.signatureRefused(w, r, audit.BadRequest)
		return
	}

	body, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil {
		g.signatureRefused(w, r, audit.BadRequest)
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.Sig)
	if err != nil {
		g.signatureRefused(w, r, audit.BadRequest)
		return
	}

	switch req.Purpose {
	case PurposeRequest:
		if req.Service == nil || req.Device != nil || req.Approval != nil {
			g.signatureRefused(w, r, audit.BadRequest)
			return
		}
		g.verifyServiceSignature(w, r, *req.Service, body, signature)

	case PurposeApproval:
		if req.Device == nil || req.Approval == nil || req.Service != nil {
			g.signatureRefused(w, r, audit.BadRequest)
			return
		}
		g.verifyApprovalSignature(w, r, *req.Device, *req.Approval, body, signature)

	case PurposeDevice:
		// A device read names no approval, because there is none: the bytes say
		// what the read is for and when it was made, and the application checks
		// the age. Accepting an approval here would let a read signature be
		// spent as a decision, so the shape is refused rather than ignored.
		if req.Device == nil || req.Approval != nil || req.Service != nil {
			g.signatureRefused(w, r, audit.BadRequest)
			return
		}
		g.verifyDeviceSignature(w, r, *req.Device, body, signature)

	default:
		g.signatureRefused(w, r, audit.BadRequest)
	}
}

// verifyServiceSignature resolves a service key and checks the signature.
func (g *Gate) verifyServiceSignature(w http.ResponseWriter, r *http.Request, id string, body, signature []byte) {
	var publicKey []byte
	var alg string
	var retired bool

	err := g.pool.QueryRow(r.Context(), store.StmtServiceKey, id).Scan(&publicKey, &alg, &retired)
	if errors.Is(err, pgx.ErrNoRows) {
		g.signatureRefused(w, r, audit.Unknown)
		return
	}
	if err != nil {
		g.signatureDatabaseError(w, r, err)
		return
	}
	if retired {
		g.signatureRefused(w, r, audit.DeviceRevoked)
		return
	}
	if err := proof.Verify(alg, publicKey, body, signature); err != nil {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}

	g.writeSignatureClaims(w, verifySignatureResponse{Kind: "service", ServiceID: id})
}

// verifyDeviceSignature resolves a device key and checks the signature, having
// first refused a device that is not live. That is the same key resolution and
// liveness check the approval path makes; the difference is that there is no
// approval to compare against, which is the point of the purpose.
//
// It reads no approvals row and so needs no approvals grant. What a read is worth
// is the application's question: this answers only "the device signed these
// bytes", and the bytes carry the read's purpose and its time so a captured
// signature expires rather than being a lasting credential.
func (g *Gate) verifyDeviceSignature(w http.ResponseWriter, r *http.Request, deviceID string, body, signature []byte) {
	publicKey, alg, userID, ok := g.deviceKey(w, r, deviceID)
	if !ok {
		return
	}
	if err := proof.Verify(alg, publicKey, body, signature); err != nil {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}

	g.writeSignatureClaims(w, verifySignatureResponse{
		Kind: "device", UserID: userID, DeviceID: deviceID,
	})
}

// deviceKey is the key and liveness read both device purposes need. The order is
// the proof path's: an unapproved or revoked device is refused before any CPU is
// spent verifying, and a missing row is the same constant refusal as a bad
// signature so a caller cannot enumerate devices.
func (g *Gate) deviceKey(w http.ResponseWriter, r *http.Request, deviceID string) (publicKey []byte, alg string, userID int64, ok bool) {
	var origin, state string
	var revoked pgtype.Timestamptz

	err := g.pool.QueryRow(r.Context(), store.StmtDeviceKey, deviceID).
		Scan(&publicKey, &alg, &origin, &state, &revoked, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		g.signatureRefused(w, r, audit.Unknown)
		return nil, "", 0, false
	}
	if err != nil {
		g.signatureDatabaseError(w, r, err)
		return nil, "", 0, false
	}
	if revoked.Valid {
		g.signatureRefused(w, r, audit.DeviceRevoked)
		return nil, "", 0, false
	}
	// A pending device is not a signer: nothing it signs has authority yet.
	if state != deviceStateLive {
		g.signatureRefused(w, r, audit.DevicePending)
		return nil, "", 0, false
	}
	return publicKey, alg, userID, true
}

// verifyApprovalSignature resolves a device key, checks it is live, and checks
// that the bytes being verified are about the approval they claim to be about.
//
// The last part is what the read on authz.approvals is for: the signed string
// carries the request's hash, and comparing it with the stored hash means a bug
// in the application cannot spend a signature against a different payload.
// Without that grant this check is impossible and the endpoint would verify
// bytes that could describe anything.
func (g *Gate) verifyApprovalSignature(w http.ResponseWriter, r *http.Request, deviceID, approvalID string, body, signature []byte) {
	publicKey, alg, userID, ok := g.deviceKey(w, r, deviceID)
	if !ok {
		return
	}
	if err := proof.Verify(alg, publicKey, body, signature); err != nil {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}

	var storedHash []byte
	var subjectID int64
	var requirement string
	err := g.pool.QueryRow(r.Context(), store.StmtApprovalHash, approvalID).
		Scan(&storedHash, &subjectID, &requirement)
	if errors.Is(err, pgx.ErrNoRows) {
		g.signatureRefused(w, r, audit.Unknown)
		return
	}
	if err != nil {
		g.signatureDatabaseError(w, r, err)
		return
	}

	// The decision string is version, approval id, request hash, decision,
	// device, seconds, expiry, issued-at (aivan-hud's Approvals.decision_canonical).
	// The hash is the third line, written as lowercase hex by the signer, and it
	// has to be the hex of the stored bytes. Encoding rather than hashing
	// again is the point: the stored value is already a digest.
	signedHash, ok := thirdLine(body)
	if !ok || signedHash != hex.EncodeToString(storedHash) {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}
	// The device has to belong to the person the approval is for — for the two
	// requirements where that is the rule.
	//
	// `self_or_admin` is the exception, and the column is why it can be: an admin
	// may decide a `self_or_admin` request that is not theirs
	// (spec §5.2, decisions §9.1), so the gate verifies the signature and the
	// application says who may act on it. Refusing here would make that decision
	// unreachable in production, because a phone has no way to reach hud except
	// through this endpoint. For `subject` and `admin` the check is unchanged: a
	// non-subject device is refused before the application is asked.
	if subjectID != userID && requirement != approvalRequirementSelfOrAdmin {
		g.signatureRefused(w, r, audit.RoleInsufficient)
		return
	}

	g.writeSignatureClaims(w, verifySignatureResponse{
		Kind: "device", UserID: userID, DeviceID: deviceID,
	})
}

// approvalRequirementSelfOrAdmin is the one value of
// authz.approvals.approver_requirement that widens who may decide beyond the
// subject. Spelled here rather than derived, because the gate reads the column as
// data and must not learn the rest of the vocabulary (spec §13).
const approvalRequirementSelfOrAdmin = "self_or_admin"

// thirdLine returns the third newline-separated field of body. The canonical
// strings in this system are newline-separated with no trailing newline, so a
// line count is a stable shape check.
func thirdLine(body []byte) (string, bool) {
	lines := 0
	start := 0
	for i, b := range body {
		if b != '\n' {
			continue
		}
		lines++
		if lines == 2 {
			start = i + 1
		}
		if lines == 3 {
			return string(body[start:i]), true
		}
	}
	return "", false
}

func (g *Gate) writeSignatureClaims(w http.ResponseWriter, claims verifySignatureResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(claims)
}

// signatureRefused writes the constant 401. The reason goes to the decision
// log, where an operator can join it to the caller's request id.
func (g *Gate) signatureRefused(w http.ResponseWriter, r *http.Request, reason audit.Reason) {
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Route: VerifySignaturePath,
		Method: http.MethodPost, Allow: false, Reason: reason, Status: http.StatusUnauthorized})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
}

func (g *Gate) signatureDatabaseError(w http.ResponseWriter, r *http.Request, err error) {
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Route: VerifySignaturePath,
		Method: http.MethodPost, Allow: false, Reason: audit.Database, Status: http.StatusServiceUnavailable})
	g.log.Error("database error", "error", audit.Error(err), "request_id", reqid.From(r.Context()))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
}

// readVerifySignatureRequest parses the one object and refuses anything else.
// Unknown fields are an error, so a future field cannot be silently ignored by
// an old process.
func readVerifySignatureRequest(r *http.Request) (verifySignatureRequest, error) {
	var req verifySignatureRequest
	if r.Body == nil {
		return req, errors.New("empty body")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, verifySignatureBodyLimit))
	if err != nil {
		return req, err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return req, errors.New("trailing data")
	}
	if req.Body == "" || req.Sig == "" || req.Purpose == "" {
		return req, errors.New("missing field")
	}
	return req, nil
}
