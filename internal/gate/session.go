package gate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/reqid"
	"github.com/chris/aivan-authz/internal/store"
)

// SessionCookie is the cookie's name, prefix included. The __Host- prefix is
// load-bearing (spec §5.4): it requires Secure, Path=/, and the absence of
// Domain, so a conforming browser will not send the cookie to a sibling host.
// Dropping any of those three attributes makes the browser reject the cookie
// outright, which is why none of them is optional here.
const SessionCookie = "__Host-aivan_session"

// Session token shape: 32 random bytes, base64url without padding. Both the
// mint and the read path enforce it, so a value that could not have been
// minted is never hashed and never reaches the database.
const (
	sessionTokenBytes = 32
	sessionTokenLen   = 43 // ceil(32*8/6)
)

// The cookies the session writes, as whole strings. http.SetCookie would add
// Expires and reorder attributes; the exact attribute set is part of what D7
// asserts, so it is written here in one place.
//
// No Max-Age on the mint cookie: server-side expiry is authoritative, and a
// browser that drops the cookie early would hide that. SameSite=Lax keeps a
// link from another site landing signed in, which Strict would not.
const (
	sessionCookieValue = SessionCookie + "=%s; Path=/; Secure; HttpOnly; SameSite=Lax"
	sessionClearValue  = SessionCookie + "=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
)

// SessionCookieHeader renders the Set-Cookie value for a minted token. The dev
// mint uses it too, so the two cannot drift.
func SessionCookieHeader(token string) string {
	return strings.Replace(sessionCookieValue, "%s", token, 1)
}

// HeaderCSRF is the header a page sends when it cannot rely on Sec-Fetch-Site.
// A custom header is enough because a cross-origin HTML form cannot set one and
// a cross-origin fetch that tries triggers a preflight Traefik does not answer
// permissively. No CORS middleware is on the gated router; if one is ever
// added, this rule weakens and must be revisited (D5).
const HeaderCSRF = "X-Aivan-Csrf"

// csrfToken bounds. The value is not compared to anything: it is a presence
// test that a cross-origin form cannot satisfy, so any well-formed token is
// accepted (spec §5.4, plan §5.6).
const (
	csrfMinLen = 16
	csrfMaxLen = 128
)

// csrfSafeMethod passes the CSRF rule unconditionally. A GET that changes state
// is an application bug this service cannot see.
func csrfSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// validCSRFToken reports whether v matches ^[A-Za-z0-9_-]{16,128}$.
func validCSRFToken(v string) bool {
	if len(v) < csrfMinLen || len(v) > csrfMaxLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// csrfRefusal returns the reason a cookie-authenticated request failed the CSRF
// rule, or "" when it passes.
//
// same-site is refused even with a header: it spans sibling subdomains, which
// is not the boundary the __Host- cookie draws. Any other value without the
// header falls back to the header requirement, which is what an old client (no
// Sec-Fetch-Site at all) and curl need.
func csrfRefusal(r *http.Request, method string) Reason {
	if csrfSafeMethod(method) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "same-origin", "none":
		return ""
	case "same-site":
		return ReasonCSRFSite
	}
	if validCSRFToken(r.Header.Get(HeaderCSRF)) {
		return ""
	}
	return ReasonCSRFMissing
}

// validSessionToken reports whether a cookie value is the shape a mint writes.
// The read path uses it so a value that could not have been minted is refused
// without a database round trip.
func validSessionToken(v string) bool {
	if len(v) != sessionTokenLen {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(raw) == sessionTokenBytes
}

// sessionToken returns the validated token from the request's cookie. A missing
// or malformed cookie is no credential, not an error: it is treated the same as
// a browser that never signed in.
func sessionToken(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || !validSessionToken(c.Value) {
		return "", false
	}
	return c.Value, true
}

// anyProofHeader reports whether the request claims a device proof. A request
// carrying any of the four is on the proof path even if the set is incomplete:
// mixing a cookie with a broken proof is a client bug, and the proof path's
// refusal is the honest answer for it (D5).
func anyProofHeader(r *http.Request) bool {
	return r.Header.Get(HeaderDevice) != "" ||
		r.Header.Get(HeaderNonce) != "" ||
		r.Header.Get(HeaderSignature) != "" ||
		r.Header.Get(HeaderTimestamp) != ""
}

// sessionForwarded resolves the request the client signed for the session
// endpoints. Those endpoints are reached through the gate's own router rather
// than through forwardAuth (D2), so a proxy sets X-Forwarded-Proto and
// X-Forwarded-Host but not X-Forwarded-Method. When the four forwarded headers
// are not all present, the request itself supplies what is missing.
func sessionForwarded(r *http.Request) (forwarded, bool) {
	if f, ok := forwardedFrom(r); ok {
		return f, true
	}
	scheme := strings.ToLower(strings.TrimSpace(r.Header.Get(hdrForwardedProto)))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	f := forwarded{
		Method: strings.ToUpper(strings.TrimSpace(r.Method)),
		Scheme: scheme,
		Host:   proof.NormalizeHost(r.Header.Get(hdrForwardedHost)),
		Target: r.URL.RequestURI(),
	}
	if f.Host == "" {
		f.Host = proof.NormalizeHost(r.Host)
	}
	if f.Host == "" || f.Target == "" || !strings.HasPrefix(f.Target, "/") {
		return f, false
	}
	return f, true
}

// route resolves host, scheme and policy for a request the way Verify does, and
// writes the refusal itself when the request is one this gate does not decide
// for. Both handlers share it so the checks cannot drift.
func (g *Gate) route(w http.ResponseWriter, r *http.Request, f forwarded) (policy.Match, bool) {
	scheme, known := g.table.Scheme(f.Host)
	if !known {
		g.refuse(w, r, http.StatusForbidden, ReasonHostUnknown, f, "host is not configured")
		return policy.Match{}, false
	}
	if f.Scheme != scheme {
		// Every configured host is https; a plaintext arrival is refused
		// before the canonical string is built (C1).
		g.refuse(w, r, http.StatusForbidden, ReasonPlainHTTP, f, "scheme is not https")
		return policy.Match{}, false
	}
	m, err := g.table.Match(f.Host, f.Target)
	if err != nil {
		g.refuse(w, r, http.StatusForbidden, ReasonHostUnknown, f, "host is not configured")
		return policy.Match{}, false
	}
	if m.Defaulted {
		// Visible on purpose: a path reaching the gate with no policy entry is
		// a routing mistake, and requiring a proof is the safe default.
		g.log.Warn("policy defaulted to authenticated",
			"host", f.Host, "target", f.Target, "request_id", reqid.From(r.Context()))
	}
	return m, true
}

// Session is the handler for /__aivan/session: POST mints, DELETE logs out.
// The route lives on the gate's own router, outside forwardAuth, because a
// cookie set on a forwardAuth 200 is not delivered to the browser without
// addAuthCookiesToResponse and the request would have been consumed as an auth
// check (D2, doc/traefik-contract.md).
func (g *Gate) Session(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		g.mintSession(w, r)
	case http.MethodDelete:
		g.logout(w, r)
	default:
		w.Header().Set("Allow", http.MethodPost+", "+http.MethodDelete)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "session is POST or DELETE")
	}
}

// mintPath is the path a mint proof must cover. Requiring the proof to name
// this endpoint means a proof captured for an application route cannot be
// replayed here to mint a cookie, and a mint cannot be replayed as an
// application request.
const mintPath = "/__aivan/session"

// mintSession exchanges a valid proof for a cookie. The proof checks are the
// verify path's, unchanged; only the response differs.
func (g *Gate) mintSession(w http.ResponseWriter, r *http.Request) {
	f, ok := sessionForwarded(r)
	if !ok {
		g.refuse(w, r, http.StatusBadRequest, ReasonForwardedMissing, f, "forwarded headers incomplete")
		return
	}
	m, ok := g.route(w, r, f)
	if !ok {
		return
	}
	if !anyProofHeader(r) {
		// Minting has no enrollment redirect: a POST cannot carry a redirect
		// target worth following, and no cookie is issued for a proof that was
		// not made.
		g.deny401(w, r, f, ReasonNoProof)
		return
	}

	// The request the client signed is this endpoint, whatever the proxy's
	// forwarded headers claim: the proof has to cover the method and path that
	// this handler acts on.
	f.Method = http.MethodPost
	f.Target = mintPath

	id, ok := g.proofIdentity(w, r, f)
	if !ok {
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

	deviceID, err := proof.ParseDeviceID(id.DeviceID)
	if err != nil {
		// Unreachable: the id was formatted from bytes that verified.
		g.deny401(w, r, f, ReasonMalformedProof)
		return
	}

	token, exp, err := g.insertSession(r.Context(), deviceID, f.Host)
	if err != nil {
		if errors.Is(err, errSessionRefused) {
			// The device was revoked, rebound or removed between the proof
			// check and the insert, which is a refusal on the same path.
			g.deny401(w, r, f, ReasonSessionRefused)
			return
		}
		g.databaseError(w, r, f, err)
		return
	}

	g.log.Debug("session minted", "device_id", id.DeviceID,
		"idle_expires_at", exp.Idle.UTC().Format(time.RFC3339),
		"absolute_expires_at", exp.Absolute.UTC().Format(time.RFC3339))

	w.Header().Set("Set-Cookie", SessionCookieHeader(token))
	// 204 with the identity headers: Phase E's dev mint reads the identity back
	// from the same headers as a verify, and a body would be a second
	// representation of what they already say.
	g.allow(w, r, f, m, &identity{
		UserID:     id.UserID,
		Username:   id.Username,
		DeviceID:   id.DeviceID,
		DeviceKind: id.DeviceKind,
		Roles:      id.Roles,
		Proof:      ProofSession,
	}, http.StatusNoContent)
}

var errSessionRefused = errors.New("gate: device did not accept a session")

// sessionExpiry is the pair of timestamps the mint statement returns.
type sessionExpiry struct {
	Idle     time.Time
	Absolute time.Time
}

// insertSession writes the one row a session is and stamps the device's
// last_seen_at in the same statement. The token goes to the client; only its
// digest is stored, so a database read does not yield a usable cookie.
func (g *Gate) insertSession(ctx context.Context, deviceID [16]byte, origin string) (string, sessionExpiry, error) {
	var raw [sessionTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", sessionExpiry{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	// The digest covers the token as the client sends it, which is the value
	// the read path re-hashes. Hashing the bytes before encoding would work
	// too, but then two spellings of the same bytes could not be told apart.
	hash := proof.SHA256Sum([]byte(token))

	var exp sessionExpiry
	err := g.pool.QueryRow(ctx, store.StmtSessionMint,
		hash[:],
		pgtype.UUID{Bytes: deviceID, Valid: true},
		origin,
		intervalValue(g.sessionIdle),
		intervalValue(g.sessionMax),
	).Scan(&exp.Idle, &exp.Absolute)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", sessionExpiry{}, errSessionRefused
	}
	if err != nil {
		return "", sessionExpiry{}, err
	}
	return token, exp, nil
}

// sessionRow is what the read statement returns. origin is not kept because the
// statement already refuses a row for another host; carrying it would invite a
// second check that could disagree with the first.
type sessionRow struct {
	id         [16]byte
	revokedAt  *time.Time
	userID     int64
	kind       string
	username   string
	userActive bool
	roles      []string
}

var errNoSession = errors.New("gate: session not found")

// readSession authenticates one cookie in one statement: it slides the idle
// expiry when that moves it by more than the window, then returns the identity
// and the device's revocation state.
func (g *Gate) readSession(ctx context.Context, token, origin string) (sessionRow, error) {
	var row sessionRow
	var id pgtype.UUID
	hash := proof.SHA256Sum([]byte(token))
	err := g.pool.QueryRow(ctx, store.StmtSessionRead,
		hash[:], intervalValue(g.sessionIdle), origin,
	).Scan(&id, &row.revokedAt, &row.userID, &row.kind,
		&row.username, &row.userActive, &row.roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errNoSession
	}
	if err != nil {
		return row, err
	}
	row.id = id.Bytes
	if row.roles == nil {
		row.roles = []string{}
	}
	return row, nil
}

// verifySession is the cookie half of the decision. It runs the same policy
// evaluation as the proof path, plus the CSRF rule that only a cookie needs.
func (g *Gate) verifySession(w http.ResponseWriter, r *http.Request, f forwarded, m policy.Match, token string) {
	row, err := g.readSession(r.Context(), token, f.Host)
	if err != nil {
		if errors.Is(err, errNoSession) {
			// Covers idle-expired, absolute-expired and unknown alike. One
			// statement cannot tell them apart, and the client does not get to
			// know (S14).
			g.deny401(w, r, f, ReasonSessionInvalid)
			return
		}
		g.databaseError(w, r, f, err)
		return
	}

	// S5: the row survived the join through authz.devices, so a revoked device
	// is visible here on the very next request. No second lookup, no waiting
	// for expiry.
	switch {
	case row.revokedAt != nil:
		g.deny401(w, r, f, ReasonDeviceRevoked)
		return
	case !row.userActive:
		g.deny401(w, r, f, ReasonUserInactive)
		return
	}

	if !safeUsername(row.username) {
		g.refuse(w, r, http.StatusForbidden, ReasonUsername, f, "username cannot be a header value")
		return
	}

	id := &identity{
		UserID:     row.userID,
		Username:   row.username,
		DeviceID:   proof.FormatDeviceID(row.id),
		DeviceKind: row.kind,
		Roles:      row.roles,
		Proof:      ProofSession,
	}

	if err := CheckClass(id, m.Class); err != nil {
		reason, _ := IsDenial(err)
		if reason == "" {
			reason = ReasonRoleInsufficient
		}
		g.refuse(w, r, http.StatusForbidden, reason, f, "role insufficient")
		return
	}

	if reason := csrfRefusal(r, f.Method); reason != "" {
		g.refuse(w, r, http.StatusForbidden, reason, f, "csrf")
		return
	}

	g.success(w, r, f, m, id)
}

// logout deletes the presented session and clears the cookie. An absent or
// unknown cookie is still 204: logging out when you are not signed in is not an
// error.
//
// DELETE cannot be sent by a cross-origin HTML form, which only offers GET and
// POST, and a cross-origin fetch with it needs a preflight, so this endpoint
// does not run the CSRF rule.
func (g *Gate) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", sessionClearValue)
	w.Header().Set("Cache-Control", "no-store")

	if token, ok := sessionToken(r); ok {
		hash := proof.SHA256Sum([]byte(token))
		if _, err := g.pool.Exec(r.Context(), store.StmtSessionDelete, hash[:]); err != nil {
			g.databaseError(w, r, forwarded{}, err)
			return
		}
	}

	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Allow: true,
		Reason: ReasonLogout, Status: http.StatusNoContent})
	w.WriteHeader(http.StatusNoContent)
}

// intervalValue binds a Go duration as a PostgreSQL interval. The SQL never
// interpolates it, so one statement has one meaning whichever client sent it.
func intervalValue(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
