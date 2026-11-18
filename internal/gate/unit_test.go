package gate

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/policy"
	"github.com/chris/aivan-authz/internal/proof"
)

// The unit tests in this file build no database. They cover behaviour that
// does not need a row: the rate limiter, the forwarded-header parsing, the
// header-value rules, and the decision log's content.

func newLimiter(now *time.Time) *rateLimiter {
	return newRateLimiter(NonceRatePerMinute, NonceBurst, func() time.Time { return *now })
}

// TestRateLimiterBurstAndRefill: burst is available immediately, the limit
// applies after it, and a minute of quiet restores the bucket.
func TestRateLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(&now)

	for i := 0; i < NonceBurst; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d within the burst was refused", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("request past the burst was allowed")
	}

	// Rate is 30/minute, so two seconds buy one token.
	now = now.Add(2 * time.Second)
	if !l.Allow("1.2.3.4") {
		t.Fatal("a token that refilled was refused")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("a second request with no token was allowed")
	}

	// A different address has its own bucket.
	if !l.Allow("5.6.7.8") {
		t.Fatal("a second address was charged for the first")
	}
}

// TestRateLimiterIsPerAddress proves one noisy address cannot spend another's
// budget, which is the whole point of keying by source.
func TestRateLimiterIsPerAddress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(&now)
	for i := 0; i < NonceBurst+5; i++ {
		l.Allow("noisy")
	}
	if l.Allow("noisy") {
		t.Fatal("noisy address was not limited")
	}
	for i := 0; i < NonceBurst; i++ {
		if !l.Allow("quiet") {
			t.Fatalf("quiet address refused on request %d", i+1)
		}
	}
}

// TestRateLimiterSweeps: buckets that have refilled and gone quiet are
// forgotten, so the map cannot grow without bound.
func TestRateLimiterSweeps(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(&now)
	for i := 0; i < 100; i++ {
		l.Allow(string(rune('a'+i%26)) + "-" + time.Now().String()[:0])
	}
	if len(l.buckets) == 0 {
		t.Fatal("no buckets created")
	}
	now = now.Add(2 * time.Minute)
	l.Allow("later")
	if len(l.buckets) != 1 {
		t.Fatalf("buckets after sweep = %d, want 1", len(l.buckets))
	}
}

// TestRateLimiterIsConcurrencySafe runs under -race; the lock is the only
// shared state.
func TestRateLimiterIsConcurrencySafe(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(&now)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l.Allow(strings.Repeat("x", i%4))
			}
		}(i)
	}
	wg.Wait()
}

func TestForwardedParsing(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		ok      bool
		want    forwarded
	}{
		{
			name: "complete",
			headers: map[string]string{
				"X-Forwarded-Method": "post",
				"X-Forwarded-Proto":  "HTTPS",
				"X-Forwarded-Host":   "AIVAN-HUD.home.arpa:443",
				"X-Forwarded-Uri":    "/a?b=1",
			},
			ok:   true,
			want: forwarded{Method: "POST", Scheme: "https", Host: "aivan-hud.home.arpa", Target: "/a?b=1"},
		},
		{
			name:    "missing method",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "h", "X-Forwarded-Uri": "/"},
			ok:      false,
		},
		{
			name:    "target without a slash",
			headers: map[string]string{"X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "h", "X-Forwarded-Uri": "evil"},
			ok:      false,
		},
		{
			name:    "missing uri",
			headers: map[string]string{"X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "h"},
			ok:      false,
		},
		{
			name:    "missing host",
			headers: map[string]string{"X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https", "X-Forwarded-Uri": "/"},
			ok:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/__aivan/verify", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got, ok := forwardedFrom(req)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Fatalf("forwarded = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSafeUsername(t *testing.T) {
	good := []string{"alice", "a.b_c-d@example", "A1", strings.Repeat("a", 128)}
	for _, s := range good {
		if !safeUsername(s) {
			t.Errorf("safeUsername(%q) = false", s)
		}
	}
	bad := []string{"", "with space", "tab\t", "newline\n", "ümlaut", "semi;colon", "com,ma",
		"quote\"", strings.Repeat("a", 129)}
	for _, s := range bad {
		if safeUsername(s) {
			t.Errorf("safeUsername(%q) = true", s)
		}
	}
}

func TestJoinRoles(t *testing.T) {
	if got := joinRoles([]string{"admin", "free"}); got != "admin,free" {
		t.Fatalf("joinRoles = %q", got)
	}
	if got := joinRoles(nil); got != "" {
		t.Fatalf("joinRoles(nil) = %q, want empty", got)
	}
}

// TestDecisionLogCarriesNoSecrets runs a decision through the logger and
// asserts the fields an operator needs and the absence of anything that could
// be a credential.
func TestDecisionLogCarriesNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	d := decisionLogger{log: log}

	req := httptest.NewRequest(http.MethodGet, "/__aivan/verify", nil)
	req.Header.Set(HeaderNonce, "nonce-value-that-must-not-be-logged")
	req.Header.Set(HeaderSignature, "signature-value-that-must-not-be-logged")

	d.write(req, decision{
		RequestID: "0123456789abcdef0123456789abcdef",
		Host:      "aivan-hud.home.arpa",
		Method:    "GET",
		Route:     "/",
		UserID:    42,
		DeviceID:  "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Allow:     false,
		Reason:    ReasonBadSignature,
		Status:    http.StatusUnauthorized,
	})

	out := buf.String()
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("log line is not one JSON object: %q", out)
	}
	for _, want := range []string{"request_id", "host", "method", "route", "user_id",
		"device_id", "decision", "reason", "status"} {
		if _, ok := rec[want]; !ok {
			t.Errorf("log line missing %q: %s", want, out)
		}
	}
	if rec["decision"] != "deny" || rec["reason"] != string(ReasonBadSignature) {
		t.Errorf("decision fields = %v/%v", rec["decision"], rec["reason"])
	}
	for _, forbidden := range []string{"nonce-value", "signature-value", "X-Aivan-Nonce", "X-Aivan-Signature"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log line contains %q: %s", forbidden, out)
		}
	}
}

// TestDecodeSignature accepts the two base64url spellings of one byte string
// and refuses anything that is not base64url.
func TestDecodeSignature(t *testing.T) {
	raw := []byte{0xbb, 0xff, 0x00, 0x01}
	unpadded := "u_8AAQ"
	padded := "u_8AAQ=="
	for _, s := range []string{unpadded, padded} {
		got, err := decodeSignature(s)
		if err != nil {
			t.Fatalf("decodeSignature(%q): %v", s, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("decodeSignature(%q) = %x, want %x", s, got, raw)
		}
	}
	for _, s := range []string{"", "not base64!", "===="} {
		if _, err := decodeSignature(s); err == nil {
			t.Errorf("decodeSignature(%q) succeeded", s)
		}
	}
}

// at builds a match the way policy.Match would for a route of this class, so a
// test reads as "the route's requirement" rather than as a bare string.
func at(class policy.Class, kinds ...string) policy.Match {
	return policy.Match{Class: class, Route: "/", Kinds: kinds}
}

// TestCheckClass covers the class gate: admin needs the role, authenticated
// needs nothing extra, and an unknown class refuses.
func TestCheckClass(t *testing.T) {
	admin := &identity{Roles: []string{"admin", "free"}}
	plain := &identity{Roles: []string{"free"}}
	none := &identity{Roles: nil}

	if err := CheckClass(admin, at(policy.ClassAdmin)); err != nil {
		t.Errorf("admin on admin route: %v", err)
	}
	for _, id := range []*identity{plain, none} {
		if err := CheckClass(id, at(policy.ClassAdmin)); err == nil {
			t.Errorf("non-admin allowed on an admin route")
		}
	}
	for _, id := range []*identity{admin, plain, none} {
		if err := CheckClass(id, at(policy.ClassAuthenticated)); err != nil {
			t.Errorf("authenticated route refused an active device: %v", err)
		}
	}
	if err := CheckClass(nil, at(policy.ClassPublic)); err != nil {
		t.Errorf("public route: %v", err)
	}
	if err := CheckClass(nil, at(policy.ClassAuthenticated)); err == nil {
		t.Error("a nil identity was allowed on an authenticated route")
	}
	if err := CheckClass(nil, at(policy.ClassAdmin)); err == nil {
		t.Error("a nil identity was allowed on an admin route")
	}
	if err := CheckClass(admin, at(policy.ClassEnrollment)); err == nil {
		t.Error("an enrollment route accepted a device identity")
	}
	if err := CheckClass(admin, at(policy.Class("operator"))); err == nil {
		t.Error("an unknown class was allowed")
	}
}

// TestConfidentialRouteChecksTheKind is the class the whole component exists
// for: a valid device of an unlisted kind is refused, a listed one is allowed,
// and the refusal carries its own reason so it is not a 403 an operator has to
// guess at.
func TestConfidentialRouteChecksTheKind(t *testing.T) {
	phone := &identity{DeviceKind: "phone", Roles: []string{"free"}}
	browser := &identity{DeviceKind: "browser", Roles: []string{"admin"}}
	panel := &identity{DeviceKind: "panel"}

	route := at(policy.ClassConfidential, "phone", "tablet")

	if err := CheckClass(phone, route); err != nil {
		t.Errorf("a phone was refused a phone-only route: %v", err)
	}
	for _, id := range []*identity{browser, panel} {
		err := CheckClass(id, route)
		reason, ok := IsDenial(err)
		if !ok || reason != ReasonDeviceKindInsufficient {
			t.Errorf("%s on a phone-only route = %v, want %s", id.DeviceKind, err, ReasonDeviceKindInsufficient)
		}
	}
	if err := CheckClass(nil, route); err == nil {
		t.Error("a nil identity was allowed on a confidential route")
	}
	// A role is not a kind: an admin's browser is still a browser.
	if err := CheckClass(browser, route); err == nil {
		t.Error("an admin's browser was allowed where only a phone may go")
	}
}

// TestAdminRouteDoesNotNarrowTheKind: `admin` keeps its class and gains nothing
// from the kind field, because narrowing /admin to one kind would lock the
// operator out of their own console under a policy change that looks unrelated.
func TestAdminRouteDoesNotNarrowTheKind(t *testing.T) {
	for _, kind := range policy.DeviceKinds {
		id := &identity{DeviceKind: kind, Roles: []string{"admin"}}
		if err := CheckClass(id, at(policy.ClassAdmin)); err != nil {
			t.Errorf("an admin's %s was refused /admin: %v", kind, err)
		}
	}
}

// TestNonceRequestParsing pins the one-field body and the 400s around it.
func TestNonceRequestParsing(t *testing.T) {
	good := `{"device":"3f2504e0-4f89-41d3-9a0c-0305e82c3301"}`
	req := httptest.NewRequest(http.MethodPost, "/__aivan/nonce", strings.NewReader(good))
	got, err := readNonceRequest(req)
	if err != nil {
		t.Fatalf("readNonceRequest: %v", err)
	}
	if want := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"; formatID(got) != want {
		t.Fatalf("device = %s, want %s", formatID(got), want)
	}

	bad := []string{
		``,
		`{}`,
		`{"device":""}`,
		`{"device":"not-a-uuid"}`,
		`{"device":"3F2504E0-4F89-41D3-9A0C-0305E82C3301"}`,
		`{"device":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","extra":1}`,
		`{"device":"3f2504e0-4f89-41d3-9a0c-0305e82c3301"} {}`,
		`not json`,
		`{"device": 3}`,
	}
	for _, body := range bad {
		req := httptest.NewRequest(http.MethodPost, "/__aivan/nonce", strings.NewReader(body))
		if _, err := readNonceRequest(req); err == nil {
			t.Errorf("readNonceRequest accepted %q", body)
		}
	}
}

func TestSourceIP(t *testing.T) {
	_, trustAll, err := parseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parseCIDR: %v", err)
	}
	g := &Gate{TrustedProxies: []*net.IPNet{trustAll}}

	req := httptest.NewRequest(http.MethodPost, "/__aivan/nonce", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := g.sourceIP(req); got != "203.0.113.9" {
		t.Fatalf("behind a trusted proxy, source = %q, want the forwarded client", got)
	}

	// An untrusted peer's own X-Forwarded-For is not read: it is
	// client-controlled.
	req = httptest.NewRequest(http.MethodPost, "/__aivan/nonce", nil)
	req.RemoteAddr = "198.51.100.7:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := g.sourceIP(req); got != "198.51.100.7" {
		t.Fatalf("untrusted peer, source = %q, want the peer address", got)
	}

	// The rightmost entry is the one the nearest proxy appended.
	req = httptest.NewRequest(http.MethodPost, "/__aivan/nonce", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.9")
	if got := g.sourceIP(req); got != "203.0.113.9" {
		t.Fatalf("multiple entries, source = %q", got)
	}
}

// TestVerifyRefusesWithoutForwardedHeaders: the gate cannot reproduce the
// target, so it refuses rather than guessing. No database is reached.
func TestVerifyRefusesWithoutForwardedHeaders(t *testing.T) {
	g := &Gate{log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	g.decide = decisionLogger{log: g.log}

	req := httptest.NewRequest(http.MethodGet, "/__aivan/verify", nil)
	rec := httptest.NewRecorder()
	g.Verify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}

func formatID(id [16]byte) string { return proof.FormatDeviceID(id) }

func parseCIDR(s string) (net.IP, *net.IPNet, error) { return net.ParseCIDR(s) }
