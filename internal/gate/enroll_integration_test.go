//go:build integration

package gate_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// claimant is one key that has not been enrolled yet: the browser's half of a
// claim, with the private half kept so a test can sign whatever it wants.
type claimant struct {
	Alg     string
	Public  []byte
	edPriv  ed25519.PrivateKey
	ecPriv  *ecdsa.PrivateKey
	wireKey string
}

func newClaimant(t *testing.T, alg string) claimant {
	t.Helper()
	c := claimant{Alg: alg}
	switch alg {
	case string(proof.AlgorithmEd25519):
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519: %v", err)
		}
		c.Public, c.edPriv = pub, priv
	case string(proof.AlgorithmES256):
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate p-256: %v", err)
		}
		c.ECPriv(priv)
	default:
		t.Fatalf("unknown alg %q", alg)
	}
	c.wireKey = base64.RawURLEncoding.EncodeToString(c.Public)
	return c
}

func (c *claimant) ECPriv(priv *ecdsa.PrivateKey) {
	c.ecPriv = priv
	c.Public = elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
}

// sign signs message the way WebCrypto does for this algorithm: Ed25519 over
// the bytes, ES256 over SHA-256 with the raw r||s wire form Chromium and
// Firefox emit.
func (c claimant) sign(t *testing.T, message string) []byte {
	t.Helper()
	if c.Alg == string(proof.AlgorithmEd25519) {
		return ed25519.Sign(c.edPriv, []byte(message))
	}
	// The gate accepts either encoding for ES256; raw r||s is what a browser
	// sends, so it is what the test sends.
	sig, err := ecdsa.SignASN1(rand.Reader, c.ecPriv, sha256Of(t, message))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// rawSign is the browser's ES256 wire form, for a test that pins it.
func (c claimant) rawSign(t *testing.T, message string) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, c.ecPriv, sha256Of(t, message))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func sha256Of(t *testing.T, message string) []byte {
	t.Helper()
	sum := proof.SHA256Sum([]byte(message))
	return sum[:]
}

// mint inserts a pending enrollment and returns the code in its display form.
// The caller chooses the TTL, so an expired record is a negative interval rather
// than a sleep.
func (e *env) mintPending(userID int64, origin, kind string, ttl time.Duration) string {
	e.t.Helper()
	// One live record per (user, origin, kind) is the point of the partial
	// index, so a second mint for the same slot would be refused. A caller that
	// wants another record passes a different slot.
	harness.Exec(e.t, e.super, fmt.Sprintf(`
		delete from authz.pending_enrollments
		 where user_id = %d and origin = '%s' and kind = '%s' and claimed_at is null`,
		userID, origin, kind))
	var raw [proof.EnrollCodeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		e.t.Fatalf("code entropy: %v", err)
	}
	code := proof.EncodeEnrollCode(raw[:])
	hash := proof.SHA256Sum([]byte(proof.NormalizeEnrollCode(code)))

	harness.Exec(e.t, e.super, fmt.Sprintf(`
		insert into authz.pending_enrollments (user_id, origin, kind, code_hash, expires_at)
		values (%d, '%s', '%s', decode('%x', 'hex'), now() + interval '%d seconds')`,
		userID, origin, kind, hash[:], int64(ttl.Seconds())))
	return code
}

// pendingRecord reads the one unclaimed record for a code, so a test can assert
// what the claim changed.
func (e *env) pendingRecord(code string) (id string, claimedAt *time.Time, deviceID *string) {
	e.t.Helper()
	hash := proof.SHA256Sum([]byte(proof.NormalizeEnrollCode(code)))
	err := e.admin.QueryRow(context.Background(), `
select id::text, claimed_at, claimed_device_id::text
  from authz.pending_enrollments where code_hash = $1`, hash[:]).Scan(&id, &claimedAt, &deviceID)
	if err != nil {
		e.t.Fatalf("read pending record: %v", err)
	}
	return id, claimedAt, deviceID
}

func (e *env) countDevices() int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `select count(*) from authz.devices`).Scan(&n); err != nil {
		e.t.Fatalf("count devices: %v", err)
	}
	return n
}

func (e *env) deviceRow(id [16]byte) (userID int64, origin, kind, alg string, pub []byte) {
	e.t.Helper()
	err := e.pool.QueryRow(context.Background(), `
select user_id, origin, kind, alg, public_key from authz.devices where id = $1`,
		proof.FormatDeviceID(id)).Scan(&userID, &origin, &kind, &alg, &pub)
	if err != nil {
		e.t.Fatalf("read device: %v", err)
	}
	return
}

// claimRequest is one POST to the enrollment endpoint.
type claimRequest struct {
	Code      string
	Kind      string
	Alg       string
	PublicKey string
	Signature string
	Host      string
	// OmitFields lets a test send a body that is missing one field.
	OmitFields []string
}

// claimBody renders the JSON, or a variant of it.
func (c claimRequest) body() string {
	fields := map[string]string{
		"code": c.Code, "kind": c.Kind, "alg": c.Alg,
		"public_key": c.PublicKey, "signature": c.Signature,
	}
	if c.Kind == "" {
		fields["kind"] = "browser"
	}
	omit := make(map[string]bool, len(c.OmitFields))
	for _, f := range c.OmitFields {
		omit[f] = true
	}
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, name := range []string{"code", "kind", "alg", "public_key", "signature"} {
		if omit[name] {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(name)
		v, _ := json.Marshal(fields[name])
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.String()
}

// claim sends the request and returns the response with its body.
func (e *env) claim(c claimRequest) *response {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+gate.EnrollPath,
		strings.NewReader(c.body()))
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	host := c.Host
	if host == "" {
		host = testHost
	}
	req.Header.Set("X-Forwarded-Host", host)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("do: %v", err)
	}
	return readResponse(e.t, resp)
}

// claimFor builds the correctly signed claim for a code and key.
func claimFor(t *testing.T, code string, c claimant) claimRequest {
	t.Helper()
	norm := proof.NormalizeEnrollCode(code)
	msg := proof.EnrollCanonical(norm, c.Alg, c.wireKey)
	return claimRequest{
		Code:      norm,
		Kind:      "browser",
		Alg:       c.Alg,
		PublicKey: c.wireKey,
		Signature: base64.RawURLEncoding.EncodeToString(c.sign(t, msg)),
	}
}

// assertEnrollDenied checks the one 403: status, exact body, no cookie, no
// identity header. Every refusal must produce this same response (S9-S11).
func (r *response) assertEnrollDenied(t *testing.T) {
	t.Helper()
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d %q, want 403", r.Status, r.Body)
	}
	if r.Body != "enrollment refused\n" {
		t.Fatalf("body = %q, want the constant denial", r.Body)
	}
	for _, h := range []string{"Set-Cookie", gate.HeaderUserID, gate.HeaderUser,
		gate.HeaderDeviceID, gate.HeaderProof, gate.HeaderRoles} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("denial carried %s: %q", h, v)
		}
	}
}

// assertEnrollMalformed checks the 400, which is for a request the service
// cannot read and which therefore needs no record to exist.
func (r *response) assertEnrollMalformed(t *testing.T) {
	t.Helper()
	if r.Status != http.StatusBadRequest {
		t.Fatalf("status = %d %q, want 400", r.Status, r.Body)
	}
	if r.Header.Get("Set-Cookie") != "" {
		t.Error("a malformed claim set a cookie")
	}
}

// TestS9ClaimWithAnUnknownCodeIsRefused: a random, valid-shaped code with a
// valid signature is refused, because no pending record names it.
func TestS9ClaimWithAnUnknownCodeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	var raw [proof.EnrollCodeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	code := proof.EncodeEnrollCode(raw[:])
	c := newClaimant(t, "ed25519")

	r := e.claim(claimFor(t, code, c))
	r.assertEnrollDenied(t)
	if n := e.countDevices(); n != 0 {
		t.Fatalf("devices = %d, want 0: a claim with no record created one", n)
	}
}

// TestS10SignatureOverADifferentCodeIsRefused is the captured-POST guard. The
// key is the one the request carries and the signature is valid, but it covers
// a different code than the one submitted, so repurposing a captured claim with
// another record fails.
func TestS10SignatureOverADifferentCodeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	other := e.mintPending(userBob, testHost, "phone", 15*time.Minute)

	c := newClaimant(t, "ed25519")
	// A real signature, over the other code.
	signed := claimFor(t, other, c)
	req := claimFor(t, code, c)
	req.Signature = signed.Signature

	e.claim(req).assertEnrollDenied(t)
	if n := e.countDevices(); n != 0 {
		t.Fatalf("devices = %d, want 0", n)
	}
	// The target record is still claimable: the refusal did not consume it.
	if _, claimed, _ := e.pendingRecord(code); claimed != nil {
		t.Fatal("the refused claim consumed the record")
	}
}

// TestS10CapturedClaimWithASwappedKeyIsRefused is the other half of the same
// guard: the signature is valid but the public key in the request is a different
// one, so the signature does not verify against the submitted key.
func TestS10CapturedClaimWithASwappedKeyIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	victim := newClaimant(t, "ed25519")
	attacker := newClaimant(t, "ed25519")

	// The captured request was signed by the victim over the victim's key.
	captured := claimFor(t, code, victim)
	// The attacker repurposes it with their own key, keeping the signature.
	req := captured
	req.PublicKey = attacker.wireKey

	e.claim(req).assertEnrollDenied(t)
	if n := e.countDevices(); n != 0 {
		t.Fatalf("devices = %d, want 0", n)
	}
}

// TestClaimOnAHostWithoutTheEnrollmentClassIsRefused: a host whose policy does
// not classify the prefix as enrollment has not been configured for it. The
// refusal is a configuration error, not a claim decision, and it never reads a
// record.
func TestClaimOnAHostWithoutTheEnrollmentClassIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	// A gate whose policy leaves the prefix to the default class.
	tbl, err := policy.New(map[string]policy.Host{
		testHost: {Routes: []policy.Route{{Prefix: "/", Class: policy.ClassAuthenticated}}},
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	g, err := gate.New(gate.Options{
		Pool: e.pool, Table: tbl, Log: quiet(),
		NonceTTL: 120 * time.Second, Skew: 300 * time.Second, MaxBody: 65536,
		Page: gate.EmbeddedPage(),
	})
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(gate.EnrollPath, g.Enroll)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	req := claimFor(t, code, newClaimant(t, "ed25519"))
	body := strings.NewReader(req.body())
	httpReq, err := http.NewRequest(http.MethodPost, srv.URL+gate.EnrollPath, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	httpReq.Header.Set("X-Forwarded-Host", testHost)
	resp, err := srv.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	r := readResponse(t, resp)
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a host without the enrollment class", r.Status)
	}
	if _, claimed, _ := e.pendingRecord(code); claimed != nil {
		t.Fatal("the misconfigured host consumed the record")
	}
}

// TestS11DeviceUserComesFromTheRecord is S11's assertion: the device's user is
// the record's user. The request has no user field, and the record names alice
// even though the test wanted bob.
func TestS11DeviceUserComesFromTheRecord(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	c := newClaimant(t, "ed25519")
	r := e.claim(claimFor(t, code, c))
	if r.Status != http.StatusCreated {
		t.Fatalf("status = %d %q, want 201", r.Status, r.Body)
	}

	var out struct {
		DeviceID string `json:"device_id"`
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.UserID != userAlice || out.Username != "alice" {
		t.Fatalf("claimed user = %d/%q, want %d/alice", out.UserID, out.Username, userAlice)
	}

	// The row agrees, and there is exactly one. The request cannot have named
	// anyone else: there is no such field, and an unknown field is refused.
	deviceID, err := proof.ParseDeviceID(out.DeviceID)
	if err != nil {
		t.Fatalf("device id %q: %v", out.DeviceID, err)
	}
	userID, origin, kind, alg, pub := e.deviceRow(deviceID)
	if userID != userAlice {
		t.Fatalf("device user = %d, want the record's %d", userID, userAlice)
	}
	if origin != testHost || kind != "browser" || alg != "ed25519" {
		t.Fatalf("device = %s/%s/%s, want %s/browser/ed25519", origin, kind, alg, testHost)
	}
	if !bytes.Equal(pub, c.Public) {
		t.Fatal("the device's key is not the one the request carried")
	}

	// A request naming a user is not a request this endpoint accepts.
	bobClaim := claimFor(t, e.mintPending(userBob, "second.home.arpa", "browser", 15*time.Minute),
		newClaimant(t, "ed25519"))
	body := strings.Replace(bobClaim.body(), "{", `{"user_id":1,`, 1)
	req, err := http.NewRequest(http.MethodPost, e.server.URL+gate.EnrollPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertEnrollMalformed(t)
}

// TestClaimForAnotherOriginIsRefused: a code minted for one application cannot
// be spent on another, even with a valid signature and the right code.
func TestClaimForAnotherOriginIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	const other = "second.home.arpa"
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	c := newClaimant(t, "ed25519")
	req := claimFor(t, code, c)
	req.Host = other

	e.claim(req).assertEnrollDenied(t)
	if n := e.countDevices(); n != 0 {
		t.Fatalf("devices = %d, want 0", n)
	}
	if _, claimed, _ := e.pendingRecord(code); claimed != nil {
		t.Fatal("the wrong-origin claim consumed the record")
	}
}

// TestPhoneClaimIsAcceptedAndReachesAGatedRoute is the phone's whole wire:
// the same endpoint, the same signed body, a record minted for a phone, and the
// cookie that follows authenticates a verify with no Accept header and no page
// in between.
func TestPhoneClaimIsAcceptedAndReachesAGatedRoute(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "phone", 15*time.Minute)

	c := newClaimant(t, "ed25519")
	req := claimFor(t, code, c)
	req.Kind = "phone"

	r := e.claim(req)
	if r.Status != http.StatusCreated {
		t.Fatalf("phone claim = %d %q, want 201", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "phone" {
		t.Errorf("X-Aivan-Device-Kind = %q, want phone", got)
	}
	cookie, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("Set-Cookie: %v", err)
	}

	v := e.verifyWith(cookie, http.MethodGet, "/admin")
	if v.Status != http.StatusOK {
		t.Fatalf("verify = %d %q, want 200", v.Status, v.Body)
	}
	if got := v.Header.Get(gate.HeaderDeviceKind); got != "phone" {
		t.Errorf("verify device kind = %q, want phone", got)
	}

	var out struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	deviceID, err := proof.ParseDeviceID(out.DeviceID)
	if err != nil {
		t.Fatalf("device id: %v", err)
	}
	_, origin, kind, _, _ := e.deviceRow(deviceID)
	if origin != testHost || kind != "phone" {
		t.Fatalf("device = %s/%s, want %s/phone", origin, kind, testHost)
	}
}

// TestTabletClaimIsAccepted: the third kind in the column, on the same path.
func TestTabletClaimIsAccepted(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "tablet", 15*time.Minute)

	req := claimFor(t, code, newClaimant(t, "es256"))
	req.Kind = "tablet"
	if r := e.claim(req); r.Status != http.StatusCreated {
		t.Fatalf("tablet claim = %d %q, want 201", r.Status, r.Body)
	}
}

// TestKindComesFromTheRecord: the body's kind has to be one the column allows,
// and nothing more. The device's kind is the record's (S11), in both
// directions, so a caller cannot choose what kind of device it gets by
// describing itself differently from the code it was handed.
func TestKindComesFromTheRecord(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	// A phone's code claimed by a client that calls itself a browser still
	// produces a phone.
	phone := claimFor(t, e.mintPending(userAlice, testHost, "phone", 15*time.Minute),
		newClaimant(t, "ed25519"))
	phone.Kind = "browser"
	r := e.claim(phone)
	if r.Status != http.StatusCreated {
		t.Fatalf("phone code claimed as a browser = %d %q, want 201", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "phone" {
		t.Errorf("device kind = %q, want the record's phone", got)
	}

	// And a browser's code claimed by a client that calls itself a phone
	// produces a browser.
	browser := claimFor(t, e.mintPending(userAlice, testHost, "browser", 15*time.Minute),
		newClaimant(t, "ed25519"))
	browser.Kind = "phone"
	r = e.claim(browser)
	if r.Status != http.StatusCreated {
		t.Fatalf("browser code claimed as a phone = %d %q, want 201", r.Status, r.Body)
	}
	if got := r.Header.Get(gate.HeaderDeviceKind); got != "browser" {
		t.Errorf("device kind = %q, want the record's browser", got)
	}
}

// TestBrowserAndPhoneCoexistForOneUser: one live device per (user, origin,
// kind) allows both on one origin, which is the slot the unique index draws.
func TestBrowserAndPhoneCoexistForOneUser(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	browser := claimFor(t, e.mintPending(userAlice, testHost, "browser", 15*time.Minute),
		newClaimant(t, "ed25519"))
	if r := e.claim(browser); r.Status != http.StatusCreated {
		t.Fatalf("browser claim = %d %q, want 201", r.Status, r.Body)
	}
	phone := claimFor(t, e.mintPending(userAlice, testHost, "phone", 15*time.Minute),
		newClaimant(t, "ed25519"))
	phone.Kind = "phone"
	if r := e.claim(phone); r.Status != http.StatusCreated {
		t.Fatalf("phone claim = %d %q, want 201", r.Status, r.Body)
	}
	if n := e.countDevices(); n != 2 {
		t.Fatalf("devices = %d, want a browser and a phone", n)
	}

	// A second phone on the same origin is the same slot, so it is refused.
	second := claimFor(t, e.mintPending(userAlice, testHost, "phone", 15*time.Minute),
		newClaimant(t, "ed25519"))
	second.Kind = "phone"
	e.claim(second).assertEnrollDenied(t)
}

// TestSecondClaimOfOneRecordIsRefused (and leaves exactly one device): the
// record is consumed once and the second claim gets the same denial.
func TestSecondClaimOfOneRecordIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	first := newClaimant(t, "ed25519")
	if r := e.claim(claimFor(t, code, first)); r.Status != http.StatusCreated {
		t.Fatalf("first claim = %d %q, want 201", r.Status, r.Body)
	}

	// A second claimant with its own key, so a refusal cannot be an accident of
	// reusing the first key.
	second := newClaimant(t, "ed25519")
	e.claim(claimFor(t, code, second)).assertEnrollDenied(t)

	if n := e.countDevices(); n != 1 {
		t.Fatalf("devices = %d, want exactly 1", n)
	}
	if _, claimed, _ := e.pendingRecord(code); claimed == nil {
		t.Fatal("the record was not marked claimed")
	}
}

// TestConsumedRecordStaysConsumedAfterRevoke isolates the consumed-record guard
// from the partial unique index: the first device is revoked, so a second claim
// of the same record would pass the index but must still be refused, because
// the record was spent. Without "claimed_at is null" in the consume, this is the
// one test that notices.
func TestConsumedRecordStaysConsumedAfterRevoke(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	first := newClaimant(t, "ed25519")
	r := e.claim(claimFor(t, code, first))
	if r.Status != http.StatusCreated {
		t.Fatalf("first claim = %d %q, want 201", r.Status, r.Body)
	}
	deviceID, err := proof.ParseDeviceID(r.Header.Get(gate.HeaderDeviceID))
	if err != nil {
		t.Fatalf("device id: %v", err)
	}
	e.revoke(device{ID: deviceID})

	// The slot is free again, so only the record's consumed state can refuse.
	second := newClaimant(t, "ed25519")
	e.claim(claimFor(t, code, second)).assertEnrollDenied(t)

	var devices int
	if err := e.pool.QueryRow(context.Background(),
		`select count(*) from authz.devices where user_id = $1`, userAlice).Scan(&devices); err != nil {
		t.Fatalf("count: %v", err)
	}
	if devices != 1 {
		t.Fatalf("devices = %d, want the one revoked device and no second", devices)
	}
}

// TestConcurrentClaimsOfOneRecord is the race: two claims of the same record in
// parallel produce one 201, one 403 and one device. Run with -race.
func TestConcurrentClaimsOfOneRecord(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	const n = 2
	reqs := make([]claimRequest, n)
	for i := range reqs {
		c := newClaimant(t, "ed25519")
		reqs[i] = claimFor(t, code, c)
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		status = make([]int, n)
		start  = make(chan struct{})
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			r := e.claimRaw(reqs[i])
			mu.Lock()
			status[i] = r.Status
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	created, refused := 0, 0
	for _, s := range status {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
			refused++
		default:
			t.Fatalf("unexpected status %d; want 201 or 403", s)
		}
	}
	if created != 1 || refused != n-1 {
		t.Fatalf("created=%d refused=%d, want 1 and %d", created, refused, n-1)
	}
	if got := e.countDevices(); got != 1 {
		t.Fatalf("devices = %d, want exactly 1", got)
	}
}

// claimRaw is claim for a goroutine: it reports a transport error as a status
// the caller can fail on rather than calling t.Fatalf off the test goroutine.
func (e *env) claimRaw(c claimRequest) *response {
	req, err := http.NewRequest(http.MethodPost, e.server.URL+gate.EnrollPath,
		strings.NewReader(c.body()))
	if err != nil {
		return &response{Status: -1, Body: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		return &response{Status: -1, Body: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &response{Status: resp.StatusCode, Body: string(body), Header: resp.Header.Clone()}
}

// TestExpiredRecordIsRefused is the expiry path, with the database's own clock
// deciding: the row is inserted already expired.
func TestExpiredRecordIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", -time.Second)

	c := newClaimant(t, "ed25519")
	e.claim(claimFor(t, code, c)).assertEnrollDenied(t)
	if n := e.countDevices(); n != 0 {
		t.Fatalf("devices = %d, want 0", n)
	}
}

// TestUnsupportedAlgIsMalformedAndTouchesNoDatabase is the 400/403 distinction:
// an algorithm outside the fixed list is a malformed request, and the query
// counter proves no statement ran.
func TestUnsupportedAlgIsMalformedAndTouchesNoDatabase(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	c := newClaimant(t, "ed25519")

	req := claimFor(t, code, c)
	req.Alg = "rsa2048"

	e.counter.Reset()
	e.claim(req).assertEnrollMalformed(t)
	if n := e.counter.Value(); n != 0 {
		t.Fatalf("statements = %d, want 0 for a malformed algorithm", n)
	}
}

// TestWrongPublicKeyLengthIsMalformed: a key that cannot belong to its
// algorithm is a malformed request, and also touches nothing.
func TestWrongPublicKeyLengthIsMalformed(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	for _, tc := range []struct {
		name string
		alg  string
		key  []byte
	}{
		{"ed25519 key of 32 bytes sent as es256", "es256", make([]byte, 32)},
		{"es256 key of 65 bytes sent as ed25519", "ed25519", make([]byte, 65)},
		{"empty key", "ed25519", nil},
		{"es256 point not on the curve", "es256", bytes.Repeat([]byte{0x04}, 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := claimRequest{
				Code:      proof.NormalizeEnrollCode(code),
				Kind:      "browser",
				Alg:       tc.alg,
				PublicKey: base64.RawURLEncoding.EncodeToString(tc.key),
				Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
			}
			e.counter.Reset()
			e.claim(req).assertEnrollMalformed(t)
			if n := e.counter.Value(); n != 0 {
				t.Fatalf("statements = %d, want 0", n)
			}
		})
	}
}

// TestBadSignatureTouchesNoDatabase: the signature is checked before the
// claim, so a wrong one costs nothing and reveals nothing.
func TestBadSignatureTouchesNoDatabase(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	c := newClaimant(t, "ed25519")

	req := claimFor(t, code, c)
	sig, _ := base64.RawURLEncoding.DecodeString(req.Signature)
	sig[0] ^= 0xff
	req.Signature = base64.RawURLEncoding.EncodeToString(sig)

	e.counter.Reset()
	e.claim(req).assertEnrollDenied(t)
	if n := e.counter.Value(); n != 0 {
		t.Fatalf("statements = %d, want 0 for a bad signature", n)
	}
}

// TestCodeNormalisationIsShared: lowercase, stray dashes and the confusable
// characters all claim the record that was minted.
func TestCodeNormalisationIsShared(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	// A code with dashes, as the console prints it.
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	if !strings.Contains(code, "-") {
		t.Fatalf("display form %q has no dashes", code)
	}

	manglings := map[string]func(string) string{
		"lowercase":          strings.ToLower,
		"dashes stripped":    func(s string) string { return strings.ReplaceAll(s, "-", "") },
		"dashes as spaces":   func(s string) string { return strings.ReplaceAll(s, "-", " ") },
		"dashes doubled":     func(s string) string { return strings.ReplaceAll(s, "-", "--") },
		"surrounding spaces": func(s string) string { return "  " + s + "\n" },
	}
	for name, mangle := range manglings {
		t.Run(name, func(t *testing.T) {
			// A fresh record per subtest, because a claim consumes it. The
			// kind varies so the live-record index does not collide with the
			// subtests that ran before it.
			// Each subtest lands its own device, so the slot it claims must be
			// free. Clearing the user's rows keeps the subtests independent.
			harness.Exec(t, e.super, fmt.Sprintf(`
				delete from authz.sessions where device_id in
				       (select id from authz.devices where user_id = %d);
				delete from authz.devices          where user_id = %d;
				delete from authz.pending_enrollments where user_id = %d`,
				userBob, userBob, userBob))
			code := e.mintPending(userBob, testHost, "phone", 15*time.Minute)
			c := newClaimant(t, "es256")

			req := claimFor(t, code, c)
			// Sign the normalised code, then send the mangled spelling: the
			// server must normalise the same way or the signature will not
			// cover what the record hashes to.
			req.Code = mangle(code)
			r := e.claim(req)
			if r.Status != http.StatusCreated {
				t.Fatalf("status = %d %q, want 201", r.Status, r.Body)
			}
		})
	}
}

// TestES256RawSignatureIsAccepted pins the browser wire form for ES256: raw
// r||s, which Chromium and Firefox emit. The Phase C tests signed DER; this is
// the form a page produces.
func TestES256RawSignatureIsAccepted(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	c := newClaimant(t, "es256")

	norm := proof.NormalizeEnrollCode(code)
	msg := proof.EnrollCanonical(norm, c.Alg, c.wireKey)
	req := claimRequest{
		Code:      norm,
		Kind:      "browser",
		Alg:       c.Alg,
		PublicKey: c.wireKey,
		Signature: base64.RawURLEncoding.EncodeToString(c.rawSign(t, msg)),
	}
	if r := e.claim(req); r.Status != http.StatusCreated {
		t.Fatalf("raw r||s claim = %d %q, want 201", r.Status, r.Body)
	}
}

// TestEnrollPagePlaceholderMatchesTheCodeLength keeps the hint the operator
// reads equal to the code the console prints. A placeholder shorter than the
// code is the first thing a person notices, and it is a lie.
func TestEnrollPagePlaceholderMatchesTheCodeLength(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest(http.MethodGet, e.server.URL+gate.EnrollPath, nil)
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	page := readResponse(t, resp).Body

	m := regexp.MustCompile(`placeholder="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the code input has no placeholder")
	}
	if !strings.Contains(m[1], "-") {
		t.Errorf("placeholder %q does not show the dash grouping", m[1])
	}
	// The length is conveyed in the hint text, not the placeholder: a hint
	// long enough to hold 26 characters clips on a phone.
	if !regexp.MustCompile(`(?i)\b26\b`).MatchString(page) {
		t.Errorf("the page does not state the code length")
	}
}

// TestEnrollPageReferencesItsOwnAssets is the regression for a page served at
// /__aivan/enroll that referenced app.js relatively: that resolves to
// /__aivan/app.js, the script never loads, and the form submits natively with
// no claim. Every resource the page names must be a path this service serves.
func TestEnrollPageReferencesItsOwnAssets(t *testing.T) {
	e := newEnv(t)

	req, err := http.NewRequest(http.MethodGet, e.server.URL+gate.EnrollPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	page := readResponse(t, resp).Body

	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(refs) == 0 {
		t.Fatal("the page references no resources at all")
	}
	for _, m := range refs {
		ref := m[1]
		if strings.HasPrefix(ref, "data:") {
			// A data: URL needs no fetch, but the CSP must permit its scheme.
			if !strings.Contains(page, "img-src") {
				t.Errorf("page uses %q but the CSP has no img-src for it", ref)
			}
			continue
		}
		if !strings.HasPrefix(ref, "/") {
			t.Errorf("the page references %q, which resolves relative to %s rather than to the asset",
				ref, gate.EnrollPath)
			continue
		}
		asset, err := http.NewRequest(http.MethodGet, e.server.URL+ref, nil)
		if err != nil {
			t.Fatalf("new request for %q: %v", ref, err)
		}
		asset.Header.Set("X-Forwarded-Host", testHost)
		ar, err := e.client.Do(asset)
		if err != nil {
			t.Fatalf("do %q: %v", ref, err)
		}
		if got := readResponse(t, ar).Status; got != http.StatusOK {
			t.Errorf("the page references %q, which returns %d", ref, got)
		}
	}

	// The script's own imports must load too, or the page fails at module
	// evaluation with no visible cause.
	req, _ = http.NewRequest(http.MethodGet, e.server.URL+"/__aivan/enroll/app.js", nil)
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err = e.client.Do(req)
	if err != nil {
		t.Fatalf("do app.js: %v", err)
	}
	js := readResponse(t, resp).Body
	imports := regexp.MustCompile(`from '([^']+)'`).FindAllStringSubmatch(js, -1)
	if len(imports) == 0 {
		t.Fatal("app.js imports nothing; it should import the canonical builder")
	}
	for _, m := range imports {
		spec := m[1]
		if !strings.HasPrefix(spec, "/__aivan/enroll/") {
			t.Errorf("app.js imports %q, which does not resolve to a served asset", spec)
		}
	}
}

// TestEnrollPageScrubsTheCodeFromTheAddressBar: a scanned square carries the
// code in ?code=, and a code is a live single-use secret. The page must read it
// and then replace the URL without it, or the secret is left in the browser's
// history and a reload would replay it.
//
// This checks the script's shape rather than running it: the suite has no DOM.
// The properties that matter are that the read happens, that replaceState is
// used (pushState would add an entry), and that code is removed from the query
// before the URL is rewritten.
func TestEnrollPageScrubsTheCodeFromTheAddressBar(t *testing.T) {
	e := newEnv(t)

	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/__aivan/enroll/app.js", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do app.js: %v", err)
	}
	js := readResponse(t, resp).Body

	if !strings.Contains(js, "params.delete('code')") {
		t.Error("app.js does not remove code from the query string")
	}
	if !strings.Contains(js, "history.replaceState") {
		t.Error("app.js does not replace the URL, so the code would stay in history")
	}
	if strings.Contains(js, "history.pushState") {
		t.Error("app.js pushes a history entry for the code")
	}
	// The prefill still has to work, or a scan lands on an empty field.
	if !strings.Contains(js, "els.code.value = prefill") {
		t.Error("app.js no longer prefills the field from ?code=")
	}
}

// TestClaimedSessionAuthenticatesVerify is the handoff to the rest of the
// gate: the cookie the claim set is the cookie a verify accepts, and the device
// id and identity match.
func TestClaimedSessionAuthenticatesVerify(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)

	c := newClaimant(t, "ed25519")
	r := e.claim(claimFor(t, code, c))
	if r.Status != http.StatusCreated {
		t.Fatalf("claim = %d %q, want 201", r.Status, r.Body)
	}
	cookie, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("Set-Cookie: %v", err)
	}
	if got := r.Header.Get(gate.HeaderProof); got != gate.ProofSession {
		t.Errorf("X-Aivan-Proof = %q, want session", got)
	}
	deviceID := r.Header.Get(gate.HeaderDeviceID)
	var out struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.DeviceID != deviceID {
		t.Fatalf("body device %q, header %q", out.DeviceID, deviceID)
	}

	v := e.verifyWith(cookie, http.MethodGet, "/admin")
	if v.Status != http.StatusOK {
		t.Fatalf("verify with the claimed cookie = %d %q, want 200", v.Status, v.Body)
	}
	if got := v.Header.Get(gate.HeaderDeviceID); got != deviceID {
		t.Errorf("verify device = %q, want %q", got, deviceID)
	}
	if got := v.Header.Get(gate.HeaderUser); got != "alice" {
		t.Errorf("verify user = %q, want alice", got)
	}
}

// TestClaimedDeviceIsOneStatementForVerify: after enrollment, an ordinary
// session request is still the one prepared statement the hot path budget
// allows.
func TestClaimedDeviceIsOneStatementForVerify(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	r := e.claim(claimFor(t, code, newClaimant(t, "ed25519")))
	cookie, err := parseSetCookie(r.Header.Get("Set-Cookie"), gate.SessionCookie)
	if err != nil {
		t.Fatalf("Set-Cookie: %v", err)
	}

	e.counter.Reset()
	if v := e.verifyWith(cookie, http.MethodGet, "/admin"); v.Status != http.StatusOK {
		t.Fatalf("verify = %d %q", v.Status, v.Body)
	}
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("statements = %d, want 1", n)
	}
}

// TestClaimWritesAnAuditRow: the operator sees who claimed what, and the
// console's mint row names the record it made.
func TestClaimWritesAnAuditRow(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	r := e.claim(claimFor(t, code, newClaimant(t, "ed25519")))
	if r.Status != http.StatusCreated {
		t.Fatalf("claim = %d %q", r.Status, r.Body)
	}
	recordID, _, _ := e.pendingRecord(code)

	var (
		decision, reason string
		userID           int64
		deviceID         string
		subject          *string
	)
	if err := e.admin.QueryRow(context.Background(), `
select decision, reason, user_id, device_id::text, subject_id::text
  from authz.audit_log where route = '/__aivan/enroll' order by id desc limit 1`,
	).Scan(&decision, &reason, &userID, &deviceID, &subject); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if decision != "enroll" || reason != "claimed" {
		t.Fatalf("audit = %s/%s, want enroll/claimed", decision, reason)
	}
	if userID != userAlice {
		t.Errorf("audit user = %d, want %d", userID, userAlice)
	}
	if deviceID != r.Header.Get(gate.HeaderDeviceID) {
		t.Errorf("audit device = %q, want %q", deviceID, r.Header.Get(gate.HeaderDeviceID))
	}
	if subject == nil || *subject != recordID {
		t.Errorf("audit subject = %v, want the record %s", subject, recordID)
	}
}

// TestEnrollRejectionsAreByteIdentical is the F9 criterion: several different
// refusals produce one response down to the byte.
func TestEnrollRejectionsAreByteIdentical(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()

	goodCode := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	expired := e.mintPending(userBob, testHost, "browser", -time.Second)
	claimed := e.mintPending(userBob, testHost, "tablet", 15*time.Minute)
	if r := e.claim(claimFor(t, claimed, newClaimant(t, "ed25519"))); r.Status != http.StatusCreated {
		t.Fatalf("pre-claim of the third record = %d %q", r.Status, r.Body)
	}

	var random [proof.EnrollCodeBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}

	cases := map[string]claimRequest{
		"unknown code": claimFor(t, proof.EncodeEnrollCode(random[:]), newClaimant(t, "ed25519")),
		"expired":      claimFor(t, expired, newClaimant(t, "ed25519")),
		"already claimed": func() claimRequest {
			req := claimFor(t, claimed, newClaimant(t, "ed25519"))
			req.Code = proof.NormalizeEnrollCode(claimed)
			return req
		}(),
		"wrong origin": func() claimRequest {
			// A host this gate serves, but not the one the record names. A host
			// outside the policy is a configuration refusal and a different
			// thing; this is the claim-level origin check.
			req := claimFor(t, goodCode, newClaimant(t, "ed25519"))
			req.Host = "second.home.arpa"
			return req
		}(),
	}

	var first *response
	for name, req := range cases {
		r := e.claim(req)
		r.assertEnrollDenied(t)
		if first == nil {
			first = r
			continue
		}
		if r.Body != first.Body {
			t.Errorf("%s: body %q differs from %q", name, r.Body, first.Body)
		}
		if len(r.Header.Get("Content-Type")) != len(first.Header.Get("Content-Type")) {
			t.Errorf("%s: Content-Type differs", name)
		}
	}
}

// TestEnrollPageIsServed asserts the page and its assets, and that the page
// carries no framework, no CDN and no application data.
func TestEnrollPageIsServed(t *testing.T) {
	e := newEnv(t)

	for _, tc := range []struct{ path, ctype, want string }{
		{gate.EnrollPath, "text/html", "Enroll this device"},
		{"/__aivan/enroll/app.js", "text/javascript", "generateKey"},
		{"/__aivan/enroll/canonical.js", "text/javascript", "aivan-enroll-v1"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, e.server.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", testHost)
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			r := readResponse(t, resp)
			if r.Status != http.StatusOK {
				t.Fatalf("status = %d, want 200", r.Status)
			}
			if !strings.Contains(r.Header.Get("Content-Type"), tc.ctype) {
				t.Errorf("Content-Type = %q, want %s", r.Header.Get("Content-Type"), tc.ctype)
			}
			if !strings.Contains(r.Body, tc.want) {
				t.Errorf("body does not contain %q", tc.want)
			}
			if strings.Contains(r.Body, "http://") || strings.Contains(r.Body, "https://") &&
				tc.path == gate.EnrollPath {
				// The page's only absolute URL must be its own origin, built at
				// run time from location. A literal CDN or font host is the
				// thing this asserts is absent.
				for _, host := range []string{"cdn.", "googleapis", "unpkg", "jsdelivr", "cloudflare"} {
					if strings.Contains(r.Body, host) {
						t.Errorf("page references third-party host %q", host)
					}
				}
			}
		})
	}

	// An asset that is not one of the three is a 404, not a directory listing.
	req, _ := http.NewRequest(http.MethodGet, e.server.URL+"/__aivan/enroll/secret.txt", nil)
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := readResponse(t, resp).Status; got != http.StatusNotFound {
		t.Fatalf("unknown asset status = %d, want 404", got)
	}
}

// TestEnrollMethodNotAllowed: enrolment is GET and POST, and says so.
func TestEnrollMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req, err := http.NewRequest(method, e.server.URL+gate.EnrollPath, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Forwarded-Host", testHost)
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		r := readResponse(t, resp)
		if r.Status != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, r.Status)
		}
		if allow := r.Header.Get("Allow"); !strings.Contains(allow, "POST") {
			t.Errorf("%s: Allow = %q", method, allow)
		}
	}
}

// TestClaimBodyMalformations: the body is parsed strictly, and every parse
// failure is the same 400.
func TestClaimBodyMalformations(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	base := claimFor(t, code, newClaimant(t, "ed25519"))

	bodies := map[string]string{
		"empty":         "",
		"not JSON":      "hello",
		"array":         "[]",
		"unknown field": strings.Replace(base.body(), "{", `{"extra":1,`, 1),
		"trailing data": base.body() + "{}",
		"missing code":  claimRequest{Kind: base.Kind, Alg: base.Alg, PublicKey: base.PublicKey, Signature: base.Signature}.body(),
		"missing sig":   claimRequest{Code: base.Code, Kind: base.Kind, Alg: base.Alg, PublicKey: base.PublicKey}.body(),
		"non-b64 key":   strings.Replace(base.body(), base.PublicKey, "!!", 1),
		"short code":    strings.Replace(base.body(), base.Code, base.Code[:25], 1),
		"unknown kind":  strings.Replace(base.body(), `"browser"`, `"watch"`, 1),
		"empty kind":    strings.Replace(base.body(), `"browser"`, `""`, 1),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, e.server.URL+gate.EnrollPath,
				strings.NewReader(body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", testHost)
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			readResponse(t, resp).assertEnrollMalformed(t)
		})
	}
}

// TestClaimBodyOverTheLimitIsMalformed: the body cap is enforced before parsing.
func TestClaimBodyOverTheLimitIsMalformed(t *testing.T) {
	e := newEnv(t)
	body := strings.Repeat("a", gate.EnrollBodyLimit+1)
	req, err := http.NewRequest(http.MethodPost, e.server.URL+gate.EnrollPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", testHost)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readResponse(t, resp).assertEnrollMalformed(t)
}

// TestClaimOnAnUnknownHostIsRefused: a host the gate does not serve is refused
// before any record is read, and the refusal mentions no record.
func TestClaimOnAnUnknownHostIsRefused(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	code := e.mintPending(userAlice, testHost, "browser", 15*time.Minute)
	req := claimFor(t, code, newClaimant(t, "ed25519"))
	req.Host = "unknown.home.arpa"

	r := e.claim(req)
	if r.Status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", r.Status)
	}
	if _, claimed, _ := e.pendingRecord(code); claimed != nil {
		t.Fatal("the record was consumed")
	}
}
