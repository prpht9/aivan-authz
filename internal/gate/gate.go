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

	"github.com/chris/aivan-authz/internal/audit"
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
//
// The set is declared once, in internal/audit, so the log writer can prove that
// what it publishes is a constant and not a value built from a request.
type Reason = audit.Reason

const (
	ReasonNoProof          = audit.NoProof
	ReasonMalformedProof   = audit.MalformedProof
	ReasonNonceUnknown     = audit.NonceUnknown
	ReasonNonceExpired     = audit.NonceExpired
	ReasonReplay           = audit.Replay
	ReasonTimestampSkewed  = audit.TimestampSkewed
	ReasonTimestampBefore  = audit.TimestampBefore
	ReasonOriginMismatch   = audit.OriginMismatch
	ReasonDeviceRevoked    = audit.DeviceRevoked
	ReasonUserInactive     = audit.UserInactive
	ReasonBadSignature     = audit.BadSignature
	ReasonAlgUnsupported   = audit.AlgUnsupported
	ReasonRoleInsufficient = audit.RoleInsufficient
	ReasonDevicePending    = audit.DevicePending
	// ReasonDeviceKindInsufficient is a valid device on a route that does not
	// accept its kind. A 403, because the proof was good.
	ReasonDeviceKindInsufficient = audit.DeviceKindInsufficient
	ReasonUsername               = audit.Username
	ReasonHostUnknown            = audit.HostUnknown
	ReasonClassDefaulted         = audit.ClassDefaulted
	ReasonPlainHTTP              = audit.PlainHTTP
	ReasonBodyTooLarge           = audit.BodyTooLarge
	ReasonDatabase               = audit.Database
	ReasonRateLimited            = audit.RateLimited
	ReasonNonceTableFull         = audit.NonceTableFull
	ReasonMethodNotAllowed       = audit.MethodNotAllowed
	ReasonForwardedMissing       = audit.ForwardedMissing
	ReasonBadRequest             = audit.BadRequest

	// Session reasons. An expired, idle-timed-out and unknown cookie are one
	// reason on purpose: one statement cannot tell them apart, and the client
	// is told nothing the 401 body does not already say (S14).
	ReasonSessionInvalid = audit.SessionInvalid
	ReasonSessionRefused = audit.SessionRefused
	ReasonLogout         = audit.Logout
	ReasonCSRFMissing    = audit.CSRFMissing
	ReasonCSRFSite       = audit.CSRFSite
	ReasonPublicRoute    = audit.PublicRoute

	// Enrollment reasons. The one the client sees is ReasonEnrollRefused in
	// every case; the others are what the decision log records for an operator.
	ReasonEnrollClaimed   = audit.EnrollClaimed
	ReasonEnrollRefused   = audit.EnrollRefused
	ReasonEnrollDuplicate = audit.EnrollDuplicate
	ReasonEnrollExpired   = audit.EnrollExpired
	ReasonEnrollCode      = audit.EnrollCode
	ReasonEnrollOrigin    = audit.EnrollOrigin
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

// deviceStateLive is the state a device row must have for any authority at all.
// The other two are `pending` (waiting for approval) and `revoked`; the SQL and
// the checks compare against this name rather than spelling the literal in each
// of the four places, so a rename cannot leave one path accepting the others.
const deviceStateLive = "live"

// occupantlessKinds are the kinds that carry no person at the device: a screen
// in a hallway or on a wall has no sign-in surface, so a proof for one reaches
// the application as a device and not as its owner
// (doc/spec-authorization.md §6.1).
//
// This is a stand-in for `authz.devices.shared`, which component 3 adds. When it
// lands the predicate becomes the row's `shared` column and this set goes away:
// a shared tablet is a real case, and a kind that happens to be shared today is
// not the same fact.
var occupantlessKinds = map[string]bool{"panel": true, "tv": true}

// identity is what a successful decision produces.
type identity struct {
	UserID     int64
	Username   string
	DeviceID   string
	DeviceKind string
	Roles      []string
	Proof      string
}

// newIdentity builds the identity for one verified device row. It is the one
// place the occupantless kinds are applied, so the proof path and the session
// path cannot disagree about what a panel reaches the application as.
//
// An occupantless kind carries no person. The row's owner is who enrolled it,
// not who is standing at it, and writing their id, name or roles would be
// exactly the ownership/occupancy confusion spec §5.4 separates: the
// application would key on a person who is not there.
func newIdentity(deviceID, kind string, userID int64, username string, roles []string, proof string) *identity {
	id := &identity{
		UserID:     userID,
		Username:   username,
		DeviceID:   deviceID,
		DeviceKind: kind,
		Roles:      roles,
		Proof:      proof,
	}
	if occupantlessKinds[kind] {
		id.UserID = 0
		id.Username = ""
		id.Roles = nil
	}
	return id
}

// hasOccupant reports whether a device of this kind is a person's own. It is the
// negation of occupantlessKinds, named the other way round because that is how
// the callers read: a username has to be a header value only when there is one.
func hasOccupant(kind string) bool { return !occupantlessKinds[kind] }

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

// CheckClass decides whether id may reach the route the policy matched. A nil
// identity has no authority, which keeps the function total for the public
// class where no identity exists.
//
// It takes the match rather than the class because a route's requirement is not
// only its class: a `confidential` route also names the device kinds it accepts,
// and a caller that passed only the class would compile while ignoring them.
// That is why the parameter changed rather than a second function appearing
// beside this one.
func CheckClass(id *identity, m policy.Match) error {
	switch m.Class {
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
		// The admin class keeps its kind check *inside* its own branch, so a
		// route declared `admin` behaves exactly as it did: /admin is not
		// narrowed to one kind here, because that would lock an operator out of
		// their own console (doc/plan-device-tiers-and-reproof.md:254-261).
		if !id.HasRole("admin") {
			return deny(ReasonRoleInsufficient)
		}
		return nil
	case policy.ClassConfidential:
		// The class test comes first, as everywhere else, so a denial names the
		// reason that actually applies. This class has no role requirement of
		// its own: any active device may reach it if its kind is listed.
		if id == nil {
			return deny(ReasonNoProof)
		}
		if !kindAllowed(id.DeviceKind, m.Kinds) {
			return deny(ReasonDeviceKindInsufficient)
		}
		return nil
	case policy.ClassEnrollment:
		// The claim route proves possession of a key with a signature over a
		// pending record, which is not an identity and cannot be carried in
		// one. Reaching this decision with a device identity therefore means
		// the request came in on a path the class was not meant for.
		return deny(ReasonNoProof)
	default:
		// An unknown class is a policy bug; refusing is the safe direction.
		return deny(ReasonRoleInsufficient)
	}
}

// classRefusalNote is the operator-facing note a class refusal carries. It says
// the reason's own word, so the log line and the `reason` field cannot describe
// two different refusals.
func classRefusalNote(reason Reason) string {
	switch reason {
	case ReasonDeviceKindInsufficient:
		return "device kind insufficient"
	case ReasonNoProof:
		return "no proof"
	default:
		return "role insufficient"
	}
}

// kindAllowed reports whether a device kind is one the route names. An empty
// list means the route does not restrict kinds, which is every class but
// confidential; policy.New refuses a confidential route with an empty list, so
// the permissive branch cannot be reached with one.
func kindAllowed(kind string, kinds []string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
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
