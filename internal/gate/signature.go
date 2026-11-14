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

// The two purposes a caller can ask about. A request is a service's, an
// approval is a device's; neither can be spent as the other.
const (
	PurposeRequest  = "request"
	PurposeApproval = "approval"
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

// verifyApprovalSignature resolves a device key, checks it is live, and checks
// that the bytes being verified are about the approval they claim to be about.
//
// The last part is what the read on authz.approvals is for: the signed string
// carries the request's hash, and comparing it with the stored hash means a bug
// in the application cannot spend a signature against a different payload.
// Without that grant this check is impossible and the endpoint would verify
// bytes that could describe anything.
func (g *Gate) verifyApprovalSignature(w http.ResponseWriter, r *http.Request, deviceID, approvalID string, body, signature []byte) {
	var publicKey []byte
	var alg, origin string
	var revoked pgtype.Timestamptz
	var userID int64

	err := g.pool.QueryRow(r.Context(), store.StmtDeviceKey, deviceID).
		Scan(&publicKey, &alg, &origin, &revoked, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		g.signatureRefused(w, r, audit.Unknown)
		return
	}
	if err != nil {
		g.signatureDatabaseError(w, r, err)
		return
	}
	if revoked.Valid {
		g.signatureRefused(w, r, audit.DeviceRevoked)
		return
	}
	if err := proof.Verify(alg, publicKey, body, signature); err != nil {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}

	var storedHash []byte
	var subjectID int64
	err = g.pool.QueryRow(r.Context(), store.StmtApprovalHash, approvalID).Scan(&storedHash, &subjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		g.signatureRefused(w, r, audit.Unknown)
		return
	}
	if err != nil {
		g.signatureDatabaseError(w, r, err)
		return
	}

	// The decision string is version, approval id, request hash, decision,
	// device, seconds, expiry (aivan-hud's Approvals.decision_canonical). The
	// hash is the third line, written as lowercase hex by the signer, and it
	// has to be the hex of the stored bytes. Encoding rather than hashing
	// again is the point: the stored value is already a digest.
	signedHash, ok := thirdLine(body)
	if !ok || signedHash != hex.EncodeToString(storedHash) {
		g.signatureRefused(w, r, audit.BadSignature)
		return
	}
	// The device has to belong to the person the approval is for. That is the
	// `subject` requirement; the `admin` requirement is aivan-hud's to enforce,
	// because a role is not a claim this service returns. A device approving
	// for someone else is refused here, before the application is asked.
	if subjectID != userID {
		g.signatureRefused(w, r, audit.RoleInsufficient)
		return
	}

	g.writeSignatureClaims(w, verifySignatureResponse{
		Kind: "device", UserID: userID, DeviceID: deviceID,
	})
}

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
