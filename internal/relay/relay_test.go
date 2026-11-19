package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/servicekey"
)

// testKey is a pair whose public half the fake relay verifies with. Nothing here
// writes to disk: the package's file handling is servicekey's test.
func testKey(t *testing.T) *servicekey.KeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return &servicekey.KeyPair{Name: "aivan-authz", Private: priv, Public: pub}
}

// fakeRelay answers one route and checks the two headers the way Relay::Auth
// does: the name resolves to a key, and the signature covers the exact bytes the
// handler received.
type fakeRelay struct {
	t        *testing.T
	key      ed25519.PublicKey
	status   int
	body     string
	seenBody []byte
	seenPath string
	seenVerb string
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.seenPath, f.seenVerb = r.URL.Path, r.Method
	if got := r.Header.Get("X-Aivan-Service"); got != "aivan-authz" {
		f.t.Errorf("X-Aivan-Service = %q, want aivan-authz", got)
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Fatalf("read body: %v", err)
	}
	f.seenBody = raw

	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Aivan-Signature"))
	if err != nil {
		f.t.Errorf("signature header is not base64: %v", err)
	} else if !ed25519.Verify(f.key, raw, sig) {
		// This is the property that matters: a signature over a re-serialised
		// body would fail here, because the handler verifies over what arrived.
		f.t.Errorf("signature does not verify over the bytes received: %q", raw)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = io.WriteString(w, f.body)
}

func newTestClient(t *testing.T, f *fakeRelay) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	key := testKey(t)
	f.key = key.Public
	c, err := New(Options{URL: srv.URL, Key: key, HTTP: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestRegisterSignsTheExactBytes: the relay verifies over the buffered body, so
// the client must sign what it sends and nothing re-encoded.
func TestRegisterSignsTheExactBytes(t *testing.T) {
	f := &fakeRelay{
		t:      t,
		status: http.StatusCreated,
		body:   `{"id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","user_id":"1","alg":"ed25519","kind":"phone","state":"live"}`,
	}
	c := newTestClient(t, f)

	device, err := c.Register(context.Background(), Registration{
		UserID:    "1",
		DeviceID:  "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Alg:       "ed25519",
		Kind:      "phone",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if device.State != "live" || device.Kind != "phone" {
		t.Errorf("device = %+v", device)
	}
	if f.seenVerb != http.MethodPost || f.seenPath != DevicesPath {
		t.Errorf("request = %s %s, want POST %s", f.seenVerb, f.seenPath, DevicesPath)
	}

	// The body is JSON with the five fields the relay parses.
	var sent map[string]string
	if err := json.Unmarshal(f.seenBody, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for _, field := range []string{"user_id", "device_id", "public_key", "alg", "kind"} {
		if sent[field] == "" {
			t.Errorf("body is missing %q: %s", field, f.seenBody)
		}
	}
}

// TestRegisterAccepts200AsARetry: the relay is idempotent on the device id, so a
// second POST is a 200 with the existing row.
func TestRegisterAccepts200AsARetry(t *testing.T) {
	f := &fakeRelay{t: t, status: http.StatusOK, body: `{"id":"d","user_id":"1","alg":"ed25519","kind":"phone","state":"live"}`}
	c := newTestClient(t, f)
	ed25519Key, _ := testKeys(t)
	if _, err := c.Register(context.Background(), Registration{
		UserID: "1", DeviceID: "d", PublicKey: ed25519Key, Alg: "ed25519", Kind: "phone",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

// TestRegisterRefusalsAreActionable: each status the relay answers has to tell an
// operator what to do next, and none of them echoes a body it cannot parse.
func TestRegisterRefusalsAreActionable(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"revoked", http.StatusConflict, `{"error":"revoked"}`, "revoked id stays dead"},
		{"unsigned", http.StatusUnauthorized, `{"error":"refused"}`, "no live service named"},
		{"payload", http.StatusUnprocessableEntity, `{"error":"payload"}`, "refused the registration's fields"},
		{"limited", http.StatusTooManyRequests, `{"error":"refused"}`, "rate limiting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRelay{t: t, status: tc.status, body: tc.body}
			c := newTestClient(t, f)
			ed25519Key, _ := testKeys(t)
			_, err := c.Register(context.Background(), Registration{
				UserID: "1", DeviceID: "d", PublicKey: ed25519Key, Alg: "ed25519", Kind: "phone",
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// testKeys returns a real 32-byte Ed25519 public key and a real 65-byte P-256
// point, both base64, because the client now checks a key's shape against its
// algorithm before it signs anything. A placeholder string would pass a length
// check by accident or fail one for the wrong reason.
func testKeys(t *testing.T) (ed25519Key, es256Key string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p-256: %v", err)
	}
	point := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(point)
}

// TestRegisterAcceptsAPhonesES256Key is the regression this exists for. An
// Android Keystore produces P-256 and nothing else, so every phone registers
// es256 — and the service key that signs the registration is Ed25519. The two
// are independent, and a check that compared them refused every phone with a
// message about "this tool's" algorithm.
func TestRegisterAcceptsAPhonesES256Key(t *testing.T) {
	f := &fakeRelay{t: t, status: http.StatusCreated, body: `{"id":"d","user_id":"1","alg":"es256","kind":"phone","state":"live"}`}
	c := newTestClient(t, f)
	_, es256Key := testKeys(t)

	device, err := c.Register(context.Background(), Registration{
		UserID: "1", DeviceID: "d", PublicKey: es256Key, Alg: "es256", Kind: "phone",
	})
	if err != nil {
		t.Fatalf("a phone's es256 key was refused: %v", err)
	}
	if device.Alg != "es256" {
		t.Errorf("device alg = %q, want es256", device.Alg)
	}
	// The service key that signed the request is still the Ed25519 one.
	if !strings.HasPrefix(c.key.Alg(), "ed25519") {
		t.Errorf("the signing key changed: %q", c.key.Alg())
	}
}

// TestRegisterAcceptsAnEd25519DeviceKey is the other half: the relay's list has
// two entries, and a browser or a test device may use the first.
func TestRegisterAcceptsAnEd25519DeviceKey(t *testing.T) {
	f := &fakeRelay{t: t, status: http.StatusCreated, body: `{"id":"d","user_id":"1","alg":"ed25519","kind":"browser","state":"live"}`}
	c := newTestClient(t, f)
	ed25519Key, _ := testKeys(t)

	if _, err := c.Register(context.Background(), Registration{
		UserID: "1", DeviceID: "d", PublicKey: ed25519Key, Alg: "ed25519", Kind: "browser",
	}); err != nil {
		t.Fatalf("an ed25519 device key was refused: %v", err)
	}
}

// TestRegistrationIsCheckedBeforeItIsSigned: a typo is a local refusal, not a
// round trip to a host across the internet.
func TestRegistrationIsCheckedBeforeItIsSigned(t *testing.T) {
	f := &fakeRelay{t: t, status: http.StatusCreated, body: `{}`}
	c := newTestClient(t, f)
	ed25519Key, es256Key := testKeys(t)

	valid := Registration{UserID: "1", DeviceID: "d", PublicKey: ed25519Key, Alg: "ed25519", Kind: "phone"}
	for name, mutate := range map[string]func(*Registration){
		"no user":    func(r *Registration) { r.UserID = "" },
		"no device":  func(r *Registration) { r.DeviceID = "" },
		"no key":     func(r *Registration) { r.PublicKey = "" },
		"bad alg":    func(r *Registration) { r.Alg = "rsa" },
		"bad kind":   func(r *Registration) { r.Kind = "toaster" },
		"panel kind": func(r *Registration) { r.Kind = "panel" },
		// A key of the wrong size for its declared algorithm is refused here
		// rather than by the relay's 422, which cannot say which field was wrong.
		"31-byte ed25519": func(r *Registration) {
			r.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
		},
		"es256 key typed ed25519": func(r *Registration) { r.PublicKey = es256Key },
		"not base64":              func(r *Registration) { r.PublicKey = "not base64!!" },
	} {
		t.Run(name, func(t *testing.T) {
			reg := valid
			mutate(&reg)
			if _, err := c.Register(context.Background(), reg); err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if f.seenBody != nil {
				t.Errorf("%s reached the network", name)
			}
		})
	}
}

// TestRetireSignsAnEmptyBody: a DELETE carries no payload, and the relay verifies
// the bytes it received, which are none.
func TestRetireSignsAnEmptyBody(t *testing.T) {
	f := &fakeRelay{t: t, status: http.StatusNoContent}
	c := newTestClient(t, f)

	if err := c.Retire(context.Background(), "3f2504e0-4f89-41d3-9a0c-0305e82c3301"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if f.seenVerb != http.MethodDelete {
		t.Errorf("verb = %s, want DELETE", f.seenVerb)
	}
	if want := DevicesPath + "/3f2504e0-4f89-41d3-9a0c-0305e82c3301"; f.seenPath != want {
		t.Errorf("path = %s, want %s", f.seenPath, want)
	}
	if len(f.seenBody) != 0 {
		t.Errorf("DELETE carried a body: %q", f.seenBody)
	}
}

// TestNewRefusesAPlaintextOrHostlessURL: a registration carries a service
// signature, and a signature over a plaintext connection is one an observer can
// replay for as long as the device lives.
func TestNewRefusesAPlaintextOrHostlessURL(t *testing.T) {
	key := testKey(t)
	for _, raw := range []string{"ftp://approval.example", "approval.example", "https://"} {
		if _, err := New(Options{URL: raw, Key: key}); err == nil {
			t.Errorf("url %q was accepted", raw)
		}
	}
}
