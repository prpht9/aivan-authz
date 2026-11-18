// Package audit owns the closed set of reason codes a decision can carry and
// the log handler that keeps secrets out of the log.
//
// It is its own package so both halves are testable without a database and so
// the gate cannot add a reason that is not declared here: every code is a
// constant in this file, and the gate's writes go through it.
package audit

// Reason is the machine-readable outcome of a decision. It is a closed set:
// All returns every value, and a value outside All is not a reason.
type Reason string

// Every reason code, grouped by the part of the design that produces it.
const (
	// Proof and authority.
	NoProof          Reason = "no_proof"
	MalformedProof   Reason = "malformed_proof"
	NonceUnknown     Reason = "nonce_unknown"
	NonceExpired     Reason = "nonce_expired"
	Replay           Reason = "replay"
	TimestampSkewed  Reason = "timestamp_skewed"
	TimestampBefore  Reason = "timestamp_before_issued"
	OriginMismatch   Reason = "origin_mismatch"
	DeviceRevoked    Reason = "device_revoked"
	UserInactive     Reason = "user_inactive"
	BadSignature     Reason = "bad_signature"
	AlgUnsupported   Reason = "alg_unsupported"
	RoleInsufficient Reason = "role_insufficient"
	// DevicePending is a device row that is waiting for approval. It is not
	// revoked and not a bad key, so it gets its own reason: an operator reading
	// a 401 needs to tell an unapproved device from a broken one.
	DevicePending Reason = "device_pending"
	// DeviceKindInsufficient is a valid device whose kind the route does not
	// accept. A 403, not a 401: the proof was good and the authority was not.
	DeviceKindInsufficient Reason = "device_kind_insufficient"
	Username               Reason = "username_unrepresentable"
	HostUnknown            Reason = "host_unknown"
	ClassDefaulted         Reason = "class_defaulted"
	PlainHTTP              Reason = "plain_http"
	BodyTooLarge           Reason = "body_too_large"
	Database               Reason = "database_error"
	RateLimited            Reason = "rate_limited"
	NonceTableFull         Reason = "nonce_table_full"
	MethodNotAllowed       Reason = "method_not_allowed"
	ForwardedMissing       Reason = "forwarded_missing"
	BadRequest             Reason = "bad_request"

	// Session reasons. An expired, idle-timed-out and unknown cookie are one
	// reason on purpose: one statement cannot tell them apart, and the client
	// is told nothing the 401 body does not already say (S14).
	SessionInvalid Reason = "session_invalid"
	SessionRefused Reason = "session_refused"
	Logout         Reason = "logout"
	CSRFMissing    Reason = "csrf_missing"
	CSRFSite       Reason = "csrf_samesite"
	PublicRoute    Reason = "public_route"

	// Enrollment reasons. The one the client sees is enroll_refused in every
	// case; the others are what the decision log records for an operator.
	EnrollClaimed   Reason = "claimed"
	EnrollRefused   Reason = "enroll_refused"
	EnrollDuplicate Reason = "enroll_duplicate"
	EnrollExpired   Reason = "enroll_expired"
	EnrollCode      Reason = "enroll_bad_code"
	EnrollOrigin    Reason = "enroll_wrong_origin"

	// Unknown is what the log carries if a reason outside the set ever reaches
	// the writer. It exists so that path is visible rather than fatal.
	Unknown Reason = "unknown"
)

// all is the declared set. It is a slice rather than a map because the only
// reader is a test that walks it and Valid, which is a short scan.
var all = []Reason{
	NoProof, MalformedProof, NonceUnknown, NonceExpired, Replay,
	TimestampSkewed, TimestampBefore, OriginMismatch, DeviceRevoked, UserInactive,
	BadSignature, AlgUnsupported, RoleInsufficient, DevicePending,
	DeviceKindInsufficient, Username, HostUnknown,
	ClassDefaulted, PlainHTTP, BodyTooLarge, Database, RateLimited,
	NonceTableFull, MethodNotAllowed, ForwardedMissing, BadRequest,
	SessionInvalid, SessionRefused, Logout, CSRFMissing, CSRFSite, PublicRoute,
	EnrollClaimed, EnrollRefused, EnrollDuplicate, EnrollExpired, EnrollCode,
	EnrollOrigin, Unknown,
}

// All returns every declared reason code.
func All() []Reason { return append([]Reason(nil), all...) }

// Valid reports whether r is one of the declared constants. Every writer of a
// decision checks it, so a value built by interpolation — a header, an error
// message — is logged as Unknown instead of being published as a reason.
func Valid(r Reason) bool {
	for _, known := range all {
		if r == known {
			return true
		}
	}
	return false
}

// OrUnknown returns r, or Unknown when r is not a declared code.
func OrUnknown(r Reason) Reason {
	if Valid(r) {
		return r
	}
	return Unknown
}
