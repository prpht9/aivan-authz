package gate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/reqid"
	"github.com/chris/aivan-authz/internal/store"
)

// Enrollment paths. The page and the claim share one prefix because the policy
// class is pinned to it; the handler decides GET from POST.
const (
	EnrollPath = policy.EnrollmentPrefix
	// EnrollBodyLimit bounds the claim body. It carries a code, an algorithm,
	// a 32- or 65-byte key and a 64-byte signature, all base64url: under 512
	// bytes of payload. Four kilobytes leaves room for JSON punctuation and a
	// future field without making a large body worth sending.
	EnrollBodyLimit = 4096
)

// enrollKind is the one kind a browser page may claim. The column allows phone
// and tablet as well, because a device of those kinds may be enrolled by other
// means later; the page is a browser and must say so.
const enrollKindBrowser = "browser"

// enrollDenialBody is the one 403 body. S9, S10 and S11 are indistinguishable to
// the client in status, body and headers, so a wrong code, an expired record, a
// claimed record and a wrong-origin claim all produce exactly these bytes.
const enrollDenialBody = "enrollment refused\n"

// claimRequest is the whole wire request. Unknown fields are refused, so a
// field a future phase adds cannot be ignored by an older gate.
type claimRequest struct {
	Code      string `json:"code"`
	Kind      string `json:"kind"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// claimResponse is the 201 body: the identity the claim created, and nothing the
// session does not already carry.
type claimResponse struct {
	DeviceID string `json:"device_id"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

// Enroll serves GET (the page) and POST (the claim) on /__aivan/enroll. It is on
// the gate's own router, so it is reached directly rather than through
// forwardAuth, and it is outside the application's request path entirely.
func (g *Gate) Enroll(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		g.enrollPage(w, r)
	case http.MethodPost:
		g.claimEnrollment(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "enroll is GET or POST")
	}
}

// enrollPage serves the one static document. It renders nothing from the
// application and holds no application data (spec §10, amendment A14).
//
// The page is served from the embedded filesystem without an ETag or a cache
// header that would let a stale copy outlive a fix. It is small and it is the
// last thing that should be wrong.
func (g *Gate) enrollPage(w http.ResponseWriter, r *http.Request) {
	if g.page == nil {
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "enroll page is not built")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The page needs no third-party origin: no CDN, no font host, no analytics.
	// A CSP that says so is the second half of "works on a LAN with no
	// internet", and it is why a compromised app on the same host cannot inject
	// a script into the page that holds a key.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "+
			"img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(g.page.Index)
	}
}

// staticPath maps the two page assets to their bodies. Anything else under the
// prefix is not a file this service serves.
const (
	enrollJSPath        = "/__aivan/enroll/app.js"
	enrollCanonicalPath = "/__aivan/enroll/canonical.js"
)

// EnrollAsset serves the page's script files, refusing every other path. It is
// a separate handler so a typo in a <script src> is a 404 rather than the page.
func (g *Gate) EnrollAsset(w http.ResponseWriter, r *http.Request) {
	if g.page == nil {
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "enroll assets are not built")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "assets are GET")
		return
	}

	var body []byte
	switch r.URL.Path {
	case enrollJSPath:
		body = g.page.JS
	case enrollCanonicalPath:
		body = g.page.Canonical
	default:
		g.refuse(w, r, http.StatusNotFound, ReasonBadRequest, forwarded{}, "no such asset")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// claimEnrollment is the one unauthenticated write path this service has. The
// order is the design:
//
//  1. Parse and normalise. A malformed request is a 400, which leaks nothing
//     because nothing is looked up.
//  2. Verify the signature against the submitted key. Self-contained, so a bad
//     signature never touches the database.
//  3. In one transaction, consume the record, insert the device and the
//     session. Zero rows from the consume is a denial with the same 403 as
//     everything else.
func (g *Gate) claimEnrollment(w http.ResponseWriter, r *http.Request) {
	f, ok := sessionForwarded(r)
	if !ok {
		g.refuse(w, r, http.StatusBadRequest, ReasonForwardedMissing, f, "forwarded headers incomplete")
		return
	}
	// The same host, scheme and policy checks the verify path uses, so the two
	// cannot drift. The class must be enrollment: a host whose policy does not
	// name this prefix has not been configured for enrollment, and defaulting
	// to a class that accepts no claim would be a silent misconfiguration.
	m, ok := g.route(w, r, f)
	if !ok {
		return
	}
	if m.Class != policy.ClassEnrollment {
		g.refuse(w, r, http.StatusForbidden, ReasonHostUnknown, f,
			"host policy does not classify "+EnrollPath+" as enrollment")
		return
	}

	req, err := readClaim(w, r)
	if err != nil {
		// Malformed is 400, not 403. It is a request the service cannot read,
		// and it reveals nothing about whether any record exists.
		g.enrollMalformed(w, r, f, "claim body")
		return
	}

	code := proof.NormalizeEnrollCode(req.Code)
	publicKey, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil {
		g.enrollMalformed(w, r, f, "public key is not base64url")
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		g.enrollMalformed(w, r, f, "signature is not base64url")
		return
	}

	// Shape checks. Each of these is a property of the request alone, so a 400
	// here tells an attacker nothing about the database.
	if !proof.ValidEnrollCode(code) {
		g.enrollMalformed(w, r, f, "code is not the minted length")
		return
	}
	if req.Kind != enrollKindBrowser {
		g.enrollMalformed(w, r, f, "kind is not browser")
		return
	}
	if !proof.Supported(req.Alg) {
		// A 400 rather than a 403, deliberately: an algorithm outside the fixed
		// list is a malformed request, not a failed enrollment (plan §5.7).
		g.enrollMalformed(w, r, f, "alg is not in the fixed list")
		return
	}
	if err := proof.ValidatePublicKey(req.Alg, publicKey); err != nil {
		g.enrollMalformed(w, r, f, "public key is not valid for its algorithm")
		return
	}

	// Step 2. The signature covers the code, the algorithm and the key as sent,
	// so it is self-contained: a wrong signature cannot reach the database.
	message := proof.EnrollCanonical(code, req.Alg, req.PublicKey)
	if err := proof.Verify(req.Alg, publicKey, []byte(message), signature); err != nil {
		g.denyEnroll(w, r, f, ReasonBadSignature)
		return
	}

	deviceID, res, err := g.claim(r.Context(), claim{
		CodeHash:  proof.SHA256Sum([]byte(code)),
		Origin:    f.Host,
		Alg:       req.Alg,
		PublicKey: publicKey,
	})
	if err != nil {
		if errors.Is(err, errClaimRefused) {
			// A wrong code, an expired record, a claimed record, a wrong-origin
			// claim and a duplicate device are all this one denial (S9, S10,
			// S11). The operator sees the real reason in the decision log.
			g.denyEnroll(w, r, f, ReasonEnrollRefused)
			return
		}
		g.databaseError(w, r, f, err)
		return
	}

	w.Header().Set("Set-Cookie", SessionCookieHeader(res.Token))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// The identity headers match what a verify of the new cookie would produce,
	// so a client that reads them here reads the same values the next request
	// carries.
	h := w.Header()
	h.Set(HeaderUserID, itoa(res.UserID))
	h.Set(HeaderUser, res.Username)
	h.Set(HeaderDeviceID, proof.FormatDeviceID(deviceID))
	h.Set(HeaderDeviceKind, res.Kind)
	h.Set(HeaderRoles, joinRoles(res.Roles))
	h.Set(HeaderProof, ProofSession)

	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: http.MethodPost,
		Route: EnrollPath, UserID: res.UserID, DeviceID: proof.FormatDeviceID(deviceID),
		Allow: true, Reason: ReasonEnrollClaimed, Status: http.StatusCreated})
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(claimResponse{
		DeviceID: proof.FormatDeviceID(deviceID),
		UserID:   res.UserID,
		Username: res.Username,
	})
}

// readClaim parses the one object with exactly the fields the claim carries.
// An absent field is refused here rather than defaulted: every field is
// required, and a missing one is a malformed request (400), not a failed claim.
func readClaim(w http.ResponseWriter, r *http.Request) (claimRequest, error) {
	var (
		req    claimRequest
		fields = map[string]*string{
			"code":       &req.Code,
			"kind":       &req.Kind,
			"alg":        &req.Alg,
			"public_key": &req.PublicKey,
			"signature":  &req.Signature,
		}
	)
	if r.Body == nil {
		return req, errors.New("empty body")
	}
	// MaxBytesReader refuses a body past the limit while it is read, so the
	// service does not buffer an unbounded request to discover it is too big.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, EnrollBodyLimit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return req, errors.New("body exceeds the claim limit")
		}
		return req, err
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	// Trailing data after the object is not a claim this endpoint accepts.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return req, errors.New("trailing data")
	}
	for name, v := range fields {
		if *v == "" {
			return req, errors.New(name + " is missing")
		}
	}
	return req, nil
}

// enrollMalformed is the 400 writer. It carries the reason in the decision log
// and a constant body, so two different malformations are not distinguishable
// by anything but the status.
func (g *Gate) enrollMalformed(w http.ResponseWriter, r *http.Request, f forwarded, note string) {
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: http.MethodPost,
		Route: EnrollPath, Allow: false, Reason: ReasonBadRequest, Status: http.StatusBadRequest})
	g.log.Warn("enrollment malformed", "note", note, "request_id", reqid.From(r.Context()))
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("malformed enrollment request\n"))
}

// enrollDenial is the single writer of the claim's 403. Status, body, headers
// and therefore byte length are identical for every refusal (S9, S10, S11).
func (g *Gate) denyEnroll(w http.ResponseWriter, r *http.Request, f forwarded, reason Reason) {
	g.decide.write(r, decision{RequestID: reqid.From(r.Context()), Host: f.Host, Method: http.MethodPost,
		Route: EnrollPath, Allow: false, Reason: reason, Status: http.StatusForbidden})
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(enrollDenialBody))
}

// claim is what the transaction needs. It holds no user id: the user comes from
// the record the consume statement returned (S11).
type claim struct {
	CodeHash  [32]byte
	Origin    string
	Alg       string
	PublicKey []byte
}

// claimResult is what a successful claim produced.
type claimResult struct {
	UserID   int64
	Username string
	Kind     string
	Roles    []string
	Token    string
}

var errClaimRefused = errors.New("gate: enrollment claim refused")

// claim consumes a pending record, creates the device it names, and mints the
// session, in one transaction. Zero rows from the consume is a refusal, and a
// concurrent claim of the same record loses the race there rather than
// inserting an orphan device.
func (g *Gate) claim(ctx context.Context, c claim) ([16]byte, claimResult, error) {
	var (
		out      claimResult
		deviceID [16]byte
	)
	if _, err := rand.Read(deviceID[:]); err != nil {
		return deviceID, out, err
	}

	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return deviceID, out, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	device := pgtype.UUID{Bytes: deviceID, Valid: true}

	var (
		recordID pgtype.UUID
		userID   int64
		origin   string
		kind     string
	)
	if err := tx.QueryRow(ctx, store.StmtEnrollClaim, device, c.CodeHash[:], c.Origin).
		Scan(&recordID, &userID, &origin, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deviceID, out, errClaimRefused
		}
		return deviceID, out, err
	}

	// The device is created with the record's user, origin and kind, never the
	// request's: the request has no user field and cannot name one (S11).
	if _, err := tx.Exec(ctx, store.StmtEnrollDevice,
		device, userID, origin, "enrolled "+kind, kind, c.PublicKey, c.Alg); err != nil {
		// A second live device of one kind is the partial unique index. Two
		// claims for two different records of the same slot can race here; the
		// race is a refusal, not a 500.
		if isUniqueViolation(err) {
			return deviceID, out, errClaimRefused
		}
		return deviceID, out, err
	}

	// The identity the response carries, read in the same transaction so the
	// response cannot describe a user that was deactivated a moment ago.
	if err := tx.QueryRow(ctx, `
select u.username, coalesce(array_agg(g.name order by g.name)
                            filter (where g.name is not null), '{}')
  from public.users u
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 where u.id = $1
 group by u.username`, userID).Scan(&out.Username, &out.Roles); err != nil {
		return deviceID, out, err
	}
	if out.Roles == nil {
		out.Roles = []string{}
	}

	// The session is the endpoint's own statement, so the row this writes is
	// the row the verify path reads.
	var token string
	if token, err = g.mintInTx(ctx, tx, device, origin); err != nil {
		if errors.Is(err, errSessionRefused) {
			return deviceID, out, errClaimRefused
		}
		return deviceID, out, err
	}

	if _, err := tx.Exec(ctx, store.EnrollAuditSQL,
		userID, device, origin, reqid.From(ctx), recordID); err != nil {
		return deviceID, out, err
	}

	if err := tx.Commit(ctx); err != nil {
		return deviceID, out, err
	}

	out.UserID = userID
	out.Kind = kind
	out.Token = token
	return deviceID, out, nil
}

// mintInTx is insertSession's statement against an open transaction. It exists
// so the claim's device insert and its session commit or roll back together.
func (g *Gate) mintInTx(ctx context.Context, tx pgx.Tx, device pgtype.UUID, origin string) (string, error) {
	var raw [sessionTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := proof.SHA256Sum([]byte(token))

	var exp sessionExpiry
	if err := tx.QueryRow(ctx, store.StmtSessionMint,
		hash[:], device, origin,
		intervalValue(g.sessionIdle), intervalValue(g.sessionMax),
	).Scan(&exp.Idle, &exp.Absolute); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errSessionRefused
		}
		return "", err
	}
	return token, nil
}

// isUniqueViolation reports PostgreSQL's unique_violation, so a race between two
// claims maps to a refusal rather than a 503.
func isUniqueViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	return errors.As(err, &s) && s.SQLState() == "23505"
}
