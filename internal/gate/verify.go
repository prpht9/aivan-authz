package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/reqid"
	"github.com/chris/aivan-authz/internal/store"
)

// denialBody is the one 401 body. S14 is why it is a constant: a client must
// not be able to tell "no such device" from "bad signature" by status, length
// or header set.
const denialBody = "authentication required: POST /__aivan/nonce\n"

// Options configure a Gate. Everything with a default is optional so the tests
// can inject a clock without building an environment.
type Options struct {
	Pool  *pgxpool.Pool
	Table *policy.Table
	Log   *slog.Logger

	NonceTTL time.Duration
	Skew     time.Duration
	MaxBody  int64

	// SessionIdle and SessionMax bound a cookie session. Zero means the
	// package defaults, which are the spec's 15 minutes and 8 hours.
	SessionIdle time.Duration
	SessionMax  time.Duration

	TrustedProxies []*net.IPNet
	Counter        *store.Counter
	Now            func() time.Time
	// RatePerMinute and RateBurst override the nonce token bucket. Zero means
	// the package constants, which is what production uses.
	RatePerMinute int
	RateBurst     int

	// Page is the embedded enrollment page. A nil Page mounts the routes but
	// answers 404, which is what a test that does not build the web directory
	// wants; a shipped binary always has one.
	Page *PageSource
}

// Gate decides requests. It is safe for concurrent use: the policy table is
// immutable after construction and the only mutable state is the rate limiter
// and the maintenance schedule, each with its own lock.
type Gate struct {
	pool   *pgxpool.Pool
	table  *policy.Table
	log    *slog.Logger
	decide decisionLogger

	nonceTTL time.Duration
	skew     time.Duration
	maxBody  int64

	// sessionIdle and sessionMax are written only through the prepared
	// statements as intervals; the idle value is also the 60 s write window's
	// unit.
	sessionIdle time.Duration
	sessionMax  time.Duration

	TrustedProxies []*net.IPNet
	counter        *store.Counter
	now            func() time.Time
	page           *PageSource

	limiter *rateLimiter
	maint   maintainer
}

// New validates and builds a Gate.
func New(o Options) (*Gate, error) {
	if o.Pool == nil {
		return nil, errors.New("gate: no database pool")
	}
	if o.Table == nil {
		return nil, errors.New("gate: no policy table")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NonceTTL <= 0 || o.Skew <= 0 {
		return nil, errors.New("gate: nonce ttl and skew must be positive")
	}
	if o.NonceTTL > o.Skew {
		return nil, errors.New("gate: nonce ttl must not exceed the skew window")
	}
	if o.MaxBody <= 0 {
		return nil, errors.New("gate: max body must be positive")
	}
	if o.SessionIdle == 0 {
		o.SessionIdle = DefaultSessionIdle
	}
	if o.SessionMax == 0 {
		o.SessionMax = DefaultSessionMax
	}
	if o.SessionIdle < 0 || o.SessionMax <= 0 || o.SessionIdle >= o.SessionMax {
		return nil, errors.New("gate: session idle must be positive and below the absolute cap")
	}

	g := &Gate{
		pool:           o.Pool,
		table:          o.Table,
		log:            o.Log,
		decide:         decisionLogger{log: o.Log},
		nonceTTL:       o.NonceTTL,
		skew:           o.Skew,
		maxBody:        o.MaxBody,
		sessionIdle:    o.SessionIdle,
		sessionMax:     o.SessionMax,
		TrustedProxies: o.TrustedProxies,
		counter:        o.Counter,
		now:            o.Now,
		page:           o.Page,
	}
	if o.RatePerMinute == 0 {
		o.RatePerMinute = NonceRatePerMinute
	}
	if o.RateBurst == 0 {
		o.RateBurst = NonceBurst
	}
	g.limiter = newRateLimiter(o.RatePerMinute, o.RateBurst, o.Now)
	g.maint.now = o.Now
	return g, nil
}

// Counter exposes the statement counter, for tests and the benchmark.
func (g *Gate) Counter() *store.Counter { return g.counter }

// Verify is the forwardAuth target. It accepts every method because
// preserveRequestMethod forwards the real one: HEAD, OPTIONS and DELETE all
// arrive here, and the method that matters is X-Forwarded-Method.
func (g *Gate) Verify(w http.ResponseWriter, r *http.Request) {
	f, ok := forwardedFrom(r)
	if !ok {
		// The gate cannot reproduce the request the client signed, so it
		// refuses rather than guessing (plan §5.1).
		g.refuse(w, r, http.StatusBadRequest, ReasonForwardedMissing, f, "forwarded headers incomplete")
		return
	}

	scheme, known := g.table.Scheme(f.Host)
	if !known {
		// A host outside AIVAN_HOSTS did not arrive through a gated route.
		g.refuse(w, r, http.StatusForbidden, ReasonHostUnknown, f, "host is not configured")
		return
	}
	if f.Scheme != scheme {
		// Every configured host is https; a plaintext arrival is refused
		// before the canonical string is built (C1).
		g.refuse(w, r, http.StatusForbidden, ReasonPlainHTTP, f, "scheme is not https")
		return
	}

	m, ok := g.route(w, r, f)
	if !ok {
		return
	}

	if m.Class == policy.ClassPublic {
		// A public path is served by a router that does not pass through the
		// gate. Reaching here means the routing is wrong, but refusing would
		// break the public page, so allow and say so.
		g.log.Warn("public path reached the gate",
			"host", f.Host, "route", m.Route, "target", f.Target,
			"request_id", reqid.From(r.Context()))
		g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host,
			Method: f.Method, Route: m.Route, Allow: true, Reason: ReasonPublicRoute, Status: http.StatusOK})
		w.WriteHeader(http.StatusOK)
		return
	}

	// A request claiming any proof header is on the proof path, cookie or not:
	// the signature covers the method, target and body, so a client that did
	// both does not also need the CSRF rule (D5). Only a cookie with no proof
	// at all is the session path.
	if anyProofHeader(r) {
		g.verifyProof(w, r, f, m)
		return
	}

	if token, ok := sessionToken(r); ok {
		g.verifySession(w, r, f, m, token)
		return
	}

	g.denyNoProof(w, r, f)
}

func (g *Gate) verifyProof(w http.ResponseWriter, r *http.Request, f forwarded, m policy.Match) {
	id, ok := g.proofIdentity(w, r, f)
	if !ok {
		// The denial is already written; every reason went through the one
		// writer in proofIdentity.
		return
	}

	if err := CheckClass(id, m.Class); err != nil {
		reason, _ := IsDenial(err)
		if reason == "" {
			reason = ReasonRoleInsufficient
		}
		g.refuse(w, r, http.StatusForbidden, reason, f, "role insufficient")
		return
	}

	g.success(w, r, f, m, id)
}

// proofIdentity verifies a signed proof and returns the identity it carries.
// It writes the denial itself and returns false when the proof is refused, so
// every caller gets the same refusal shape.
func (g *Gate) proofIdentity(w http.ResponseWriter, r *http.Request, f forwarded) (*identity, bool) {
	deviceHeader := r.Header.Get(HeaderDevice)
	nonceHeader := r.Header.Get(HeaderNonce)
	signatureHeader := r.Header.Get(HeaderSignature)
	timestampHeader := r.Header.Get(HeaderTimestamp)

	if deviceHeader == "" && nonceHeader == "" && signatureHeader == "" && timestampHeader == "" {
		g.denyNoProof(w, r, f)
		return nil, false
	}
	if deviceHeader == "" || nonceHeader == "" || signatureHeader == "" || timestampHeader == "" {
		g.deny401(w, r, f, ReasonMalformedProof)
		return nil, false
	}

	deviceID, err := proof.ParseDeviceID(deviceHeader)
	if err != nil {
		g.deny401(w, r, f, ReasonMalformedProof)
		return nil, false
	}
	nonceBytes, err := decodeNonce(nonceHeader)
	if err != nil {
		g.deny401(w, r, f, ReasonMalformedProof)
		return nil, false
	}
	timestamp, err := proof.ParseTimestamp(timestampHeader)
	if err != nil {
		g.deny401(w, r, f, ReasonMalformedProof)
		return nil, false
	}
	signature, err := decodeSignature(signatureHeader)
	if err != nil {
		g.deny401(w, r, f, ReasonMalformedProof)
		return nil, false
	}

	bodyHash, ok := g.bodyDigest(w, r, f.Method)
	if !ok {
		g.refuse(w, r, http.StatusRequestEntityTooLarge, ReasonBodyTooLarge, f, "body exceeds AIVAN_MAX_BODY")
		return nil, false
	}

	canonical := proof.Canonical(proof.Request{
		Method:     f.Method,
		Scheme:     f.Scheme,
		Host:       f.Host,
		Target:     f.Target,
		BodySHA256: bodyHash,
		Nonce:      nonceHeader,
		Timestamp:  timestampHeader,
	})

	// The consume statement is the whole database cost of a successful
	// request. Everything after it reads only what it returned.
	row, err := g.consume(r.Context(), proof.SHA256Sum(nonceBytes), deviceID)
	if err != nil {
		if errors.Is(err, errNoNonce) {
			// A nonce with no matching row covers four different situations,
			// one of which — a device id that has no device row — would
			// otherwise return before the signature work and be measurably
			// faster. The dummy verification below spends the same order of
			// time on that path so the refusal does not advertise which
			// situation it was (S14).
			_ = proof.Verify(string(proof.AlgorithmEd25519), dummy.key, []byte(canonical), dummy.signature)
			g.deny401(w, r, f, ReasonNonceUnknown)
			return nil, false
		}
		g.databaseError(w, r, f, err)
		return nil, false
	}

	now := g.now()
	skew := g.skew
	switch {
	case timestamp < row.issuedAt.Unix():
		g.deny401(w, r, f, ReasonTimestampBefore)
		return nil, false
	case timestamp > now.Unix()+int64(skew/time.Second),
		timestamp < now.Unix()-int64(skew/time.Second):
		g.deny401(w, r, f, ReasonTimestampSkewed)
		return nil, false
	case row.origin != f.Host:
		// S21: a key enrolled for one application is refused by another even
		// with a valid signature.
		g.deny401(w, r, f, ReasonOriginMismatch)
		return nil, false
	case row.revokedAt != nil:
		g.deny401(w, r, f, ReasonDeviceRevoked)
		return nil, false
	case !row.userActive:
		// Before the signature check on purpose: an inactive user is refused
		// without spending CPU on a verification.
		g.deny401(w, r, f, ReasonUserInactive)
		return nil, false
	}

	if !proof.Supported(row.alg) {
		// S17: the algorithm comes from devices.alg, never from a request
		// field, so a client has no vote.
		g.deny401(w, r, f, ReasonAlgUnsupported)
		return nil, false
	}
	if err := proof.Verify(row.alg, row.publicKey, []byte(canonical), signature); err != nil {
		g.deny401(w, r, f, ReasonBadSignature)
		return nil, false
	}

	if !safeUsername(row.username) {
		g.refuse(w, r, http.StatusForbidden, ReasonUsername, f, "username cannot be a header value")
		return nil, false
	}

	return &identity{
		UserID:     row.userID,
		Username:   row.username,
		DeviceID:   proof.FormatDeviceID(row.id),
		DeviceKind: row.kind,
		Roles:      row.roles,
		Proof:      ProofNonce,
	}, true
}

// success writes the identity headers and the 200 the application's identity
// comes from. Every allow path ends here so the header set cannot drift.
func (g *Gate) success(w http.ResponseWriter, r *http.Request, f forwarded, m policy.Match, id *identity) {
	g.allow(w, r, f, m, id, http.StatusOK)
}

// allow is success with an explicit status, for the mint's 204.
func (g *Gate) allow(w http.ResponseWriter, r *http.Request, f forwarded, m policy.Match, id *identity, status int) {
	h := w.Header()
	h.Set(HeaderUserID, strconv.FormatInt(id.UserID, 10))
	h.Set(HeaderUser, id.Username)
	h.Set(HeaderDeviceID, id.DeviceID)
	h.Set(HeaderDeviceKind, id.DeviceKind)
	h.Set(HeaderRoles, joinRoles(id.Roles))
	h.Set(HeaderProof, id.Proof)
	h.Set("Cache-Control", "no-store")

	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: f.Method,
		Route: m.Route, UserID: id.UserID, DeviceID: id.DeviceID, Allow: true, Status: status})
	w.WriteHeader(status)
}

// dummy is a real key and a real signature over a fixed message, used only so
// the no-row denial path performs the full verification arithmetic. A zero key
// or zero signature could fail fast in point decoding, which would leave the
// timing difference the dummy exists to remove.
var dummy = func() struct{ key, signature []byte } {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		// A gate that cannot generate a key cannot generate request ids or
		// nonces either, so there is nothing to degrade to.
		panic("gate: entropy unavailable: " + err.Error())
	}
	return struct{ key, signature []byte }{
		key:       pub,
		signature: ed25519.Sign(priv, []byte("aivan-dummy")),
	}
}()

// verifyRow is the single row the consume statement returns.
type verifyRow struct {
	id         [16]byte
	publicKey  []byte
	alg        string
	kind       string
	revokedAt  *time.Time
	userID     int64
	origin     string
	username   string
	userActive bool
	issuedAt   time.Time
	roles      []string
}

var errNoNonce = errors.New("gate: nonce not consumed")

// consume runs the one prepared statement. A second use of a nonce deletes no
// row, so a replay returns no rows and loses the race (S1).
func (g *Gate) consume(ctx context.Context, nonceHash [32]byte, deviceID [16]byte) (verifyRow, error) {
	var row verifyRow
	err := g.pool.QueryRow(ctx, store.StmtVerify, nonceHash[:], deviceID).Scan(
		&row.id, &row.publicKey, &row.alg, &row.kind, &row.revokedAt, &row.userID,
		&row.origin, &row.username, &row.userActive, &row.issuedAt, &row.roles,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errNoNonce
	}
	if err != nil {
		return row, err
	}
	if row.roles == nil {
		row.roles = []string{}
	}
	return row, nil
}

// bodyDigest hashes the body exactly once. Methods that cannot carry a body we
// hash use the empty-body digest and the body is not read at all (C7).
func (g *Gate) bodyDigest(w http.ResponseWriter, r *http.Request, method string) (string, bool) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		return proof.EmptyBodySHA256, true
	}
	if r.Body == nil {
		return proof.EmptyBodySHA256, true
	}

	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	var buf []byte
	var err error
	if buf, err = io.ReadAll(r.Body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", false
		}
		// A body that dies mid-read cannot be hashed, so it cannot be
		// verified. Treated as a proof that does not match.
		return "", true
	}
	return proof.SHA256Hex(buf), true
}

// denyNoProof follows the denial matrix: an HTML navigation is redirected to
// the enrollment page, everything else gets the constant 401. A non-GET method
// is never redirected, because redirecting a body loses it.
func (g *Gate) denyNoProof(w http.ResponseWriter, r *http.Request, f forwarded) {
	html := false
	for _, v := range r.Header.Values("Accept") {
		if containsToken(v, "text/html") {
			html = true
			break
		}
	}
	if html && (f.Method == http.MethodGet || f.Method == http.MethodHead) {
		w.Header().Set("Location", "/__aivan/enroll?rd="+url.QueryEscape(f.Target))
		w.Header().Set("Cache-Control", "no-store")
		g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: f.Method,
			Allow: false, Reason: ReasonNoProof, Status: http.StatusFound})
		w.WriteHeader(http.StatusFound)
		return
	}
	g.deny401(w, r, f, ReasonNoProof)
}

// deny401 is the single writer of the 401 response. Every reason goes through
// it so the response cannot drift between reasons (S14).
func (g *Gate) deny401(w http.ResponseWriter, r *http.Request, f forwarded, reason Reason) {
	h := w.Header()
	h.Set("WWW-Authenticate", "Aivan")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: f.Method,
		Allow: false, Reason: reason, Status: http.StatusUnauthorized})
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(denialBody))
}

// refuse writes an empty-bodied refusal and logs it. A 403 is a valid proof
// with insufficient authority, which is the client's business; every other
// status is a condition an operator should see.
func (g *Gate) refuse(w http.ResponseWriter, r *http.Request, status int, reason Reason, f forwarded, note string) {
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: f.Method,
		Allow: false, Reason: reason, Status: status})
	if status != http.StatusForbidden {
		g.log.Warn("refused", "reason", string(reason), "note", note,
			"request_id", reqid.From(r.Context()))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

func (g *Gate) databaseError(w http.ResponseWriter, r *http.Request, f forwarded, err error) {
	// The error is logged without the DSN: pgx errors can carry the
	// connection string, so only the message shape is quoted.
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: f.Method,
		Allow: false, Reason: ReasonDatabase, Status: http.StatusServiceUnavailable})
	g.log.Error("database error", "error", err.Error(), "request_id", reqid.From(r.Context()))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func containsToken(header, token string) bool {
	return strings.Contains(strings.ToLower(header), token)
}
