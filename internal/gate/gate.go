// Package gate implements the request decision: prove the device, apply
// policy, return identity headers or a denial.
//
// It is separate from package httpx so the decision logic can be tested without
// a listener, and so the wire details of one handler do not leak into another.
package gate

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/chris/aivan-authz/internal/policy"
)

// Proof header names. These four are the only X-Aivan-* request headers the
// gate reads. Traefik strips response headers matching ^X-Aivan- from the
// request to the application, but it does not strip them from the request to
// this service, so identity headers (X-Aivan-User and friends) must be treated
// as untrusted input and are never read here.
const (
	HeaderDevice    = "X-Aivan-Device"
	HeaderNonce     = "X-Aivan-Nonce"
	HeaderSignature = "X-Aivan-Signature"
	HeaderTimestamp = "X-Aivan-Timestamp"
)

// Identity and integrity headers the gate sets on success. Values are opaque to
// the application.
const (
	HeaderUserID     = "X-Aivan-User-Id"
	HeaderUser       = "X-Aivan-User"
	HeaderDeviceID   = "X-Aivan-Device-Id"
	HeaderDeviceKind = "X-Aivan-Device-Kind"
	HeaderRoles      = "X-Aivan-Roles"
	HeaderProof      = "X-Aivan-Proof"
	// HeaderRequestID is re-exported so a test can ignore it when comparing
	// whole responses; the generator lives in internal/reqid.
	HeaderRequestID = "X-Aivan-Request-Id"
)

// Proof mechanism names for X-Aivan-Proof.
const (
	ProofNonce   = "nonce"
	ProofMTLS    = "mtls"
	ProofSession = "session"
)

// Session lifetime defaults, from spec §5.4. Idle slides and is written back
// only when it moves more than sessionIdleWindow; the absolute cap never moves.
const (
	DefaultSessionIdle = 15 * time.Minute
	DefaultSessionMax  = 8 * time.Hour
)

// Denial is every way a request can be refused, after the database work has
// happened. The client sees one constant 401 body for all of them (S14); the
// operator sees Reason in the decision log.
type Reason string

const (
	ReasonNoProof          Reason = "no_proof"
	ReasonMalformedProof   Reason = "malformed_proof"
	ReasonNonceUnknown     Reason = "nonce_unknown"
	ReasonNonceExpired     Reason = "nonce_expired"
	ReasonReplay           Reason = "replay"
	ReasonTimestampSkewed  Reason = "timestamp_skewed"
	ReasonTimestampBefore  Reason = "timestamp_before_issued"
	ReasonOriginMismatch   Reason = "origin_mismatch"
	ReasonDeviceRevoked    Reason = "device_revoked"
	ReasonUserInactive     Reason = "user_inactive"
	ReasonBadSignature     Reason = "bad_signature"
	ReasonAlgUnsupported   Reason = "alg_unsupported"
	ReasonRoleInsufficient Reason = "role_insufficient"
	ReasonUsername         Reason = "username_unrepresentable"
	ReasonHostUnknown      Reason = "host_unknown"
	ReasonClassDefaulted   Reason = "class_defaulted"
	ReasonPlainHTTP        Reason = "plain_http"
	ReasonBodyTooLarge     Reason = "body_too_large"
	ReasonDatabase         Reason = "database_error"
	ReasonRateLimited      Reason = "rate_limited"
	ReasonNonceTableFull   Reason = "nonce_table_full"
	ReasonMethodNotAllowed Reason = "method_not_allowed"
	ReasonForwardedMissing Reason = "forwarded_missing"
	ReasonBadRequest       Reason = "bad_request"

	// Session reasons. An expired, idle-timed-out and unknown cookie are one
	// reason on purpose: one statement cannot tell them apart, and the client
	// is told nothing the 401 body does not already say (S14).
	ReasonSessionInvalid Reason = "session_invalid"
	ReasonSessionRefused Reason = "session_refused"
	ReasonLogout         Reason = "logout"
	ReasonCSRFMissing    Reason = "csrf_missing"
	ReasonCSRFSite       Reason = "csrf_samesite"
	ReasonPublicRoute    Reason = "public_route"
)

// IsDenial returns the reason for err when err is one of the denial reasons
// above, and "" otherwise. Denials are carried as errors because they happen
// inside deeply nested checks, but they are not exceptional.
func IsDenial(err error) (Reason, bool) {
	var d *DenialError
	if errors.As(err, &d) {
		return d.Reason, true
	}
	return "", false
}

// DenialError carries a reason code through the normal error return.
type DenialError struct{ Reason Reason }

func (d *DenialError) Error() string { return "denied: " + string(d.Reason) }

// deny is the constructor. It returns an error rather than panicking or
// returning a sentinel, so a missing check is a compile-time problem.
func deny(r Reason) error { return &DenialError{Reason: r} }

// identity is what a successful decision produces.
type identity struct {
	UserID     int64
	Username   string
	DeviceID   string
	DeviceKind string
	Roles      []string
	Proof      string
}

// HasRole reports membership. Roles arrive sorted from the database, so a
// linear scan over a short slice is faster than a map and cannot outlive its
// allocation.
func (id *identity) HasRole(role string) bool {
	if id == nil {
		return false
	}
	for _, r := range id.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// CheckClass decides whether id may reach a route of class c. A nil identity
// has no authority, which keeps the function total for the public class where
// no identity exists.
func CheckClass(id *identity, c policy.Class) error {
	switch c {
	case policy.ClassPublic:
		// No proof required, and the caller sets no headers. A public request
		// never reaches the identity path at all, but this keeps the function
		// total.
		return nil
	case policy.ClassAuthenticated:
		if id == nil {
			return deny(ReasonNoProof)
		}
		return nil
	case policy.ClassAdmin:
		if !id.HasRole("admin") {
			return deny(ReasonRoleInsufficient)
		}
		return nil
	default:
		// An unknown class is a policy bug; refusing is the safe direction.
		return deny(ReasonRoleInsufficient)
	}
}

// decodeSignature accepts base64url with or without padding, because the
// browser's base64url helper emits unpadded while some clients pad. Both decode
// to the same bytes, so accepting both is not a second wire format for the
// signature itself.
func decodeSignature(s string) ([]byte, error) {
	if s == "" {
		return nil, deny(ReasonMalformedProof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(s); err != nil {
			return nil, deny(ReasonMalformedProof)
		}
	}
	return raw, nil
}

// encodeNonce is base64url without padding, the same encoding the browser
// helper and the signature header use.
func encodeNonce(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// decodeNonce reverses encodeNonce.
func decodeNonce(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, deny(ReasonMalformedProof)
	}
	if len(raw) == 0 {
		return nil, deny(ReasonMalformedProof)
	}
	return raw, nil
}

// S15 note. The service performs no variable-time comparison of secret material
// in Go. The nonce comparison is a primary-key equality on a fixed 32-byte
// digest inside PostgreSQL, signature verification is library code, and the
// session token's lookup is the same primary-key equality on a 32-byte SHA-256
// digest. The token itself is never compared: the database sees only its hash,
// so there is no secret whose timing could vary with proximity to a guess.

// safeUsername reports whether a username can be a header value as-is. The
// contract refuses unrepresentable names rather than encoding them, because an
// encoded name is a second spelling of an identity (spec §6.1).
func safeUsername(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// joinRoles renders the role list as the contract specifies: sorted, comma
// separated, no spaces. The database sorts them; this does not assume it
// without also being total for an empty list.
func joinRoles(roles []string) string { return strings.Join(roles, ",") }
