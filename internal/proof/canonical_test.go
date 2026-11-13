package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vector is one entry of testdata/canonical.json. The browser implementation
// reads the same file at Phase F, so it stays a flat array of objects with no
// nesting and no field beyond these.
type vector struct {
	Name       string `json:"name"`
	Method     string `json:"method"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Target     string `json:"target"`
	BodySHA256 string `json:"body_sha256"`
	Nonce      string `json:"nonce"`
	Timestamp  string `json:"timestamp"`
	Expected   string `json:"expected"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "canonical.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(body, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

func (v vector) request() Request {
	return Request{
		Method: v.Method, Scheme: v.Scheme, Host: v.Host, Target: v.Target,
		BodySHA256: v.BodySHA256, Nonce: v.Nonce, Timestamp: v.Timestamp,
	}
}

// TestCanonicalVectors is C8's first unit test: every vector produces its
// expected bytes exactly. A drift in field order, separator or encoding shows
// up here before it shows up as a refused browser.
func TestCanonicalVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if got := Canonical(v.request()); got != v.Expected {
				t.Fatalf("Canonical() =\n%q\nwant\n%q", got, v.Expected)
			}
		})
	}
}

// TestVectorBodyHashes checks the body hashes in the file rather than trusting
// them. The third vector's hash is sha256("hello").
func TestVectorBodyHashes(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.BodySHA256 != EmptyBodySHA256 && v.BodySHA256 != SHA256Hex([]byte("hello")) {
			t.Errorf("%s: body_sha256 %q matches neither an empty body nor \"hello\"", v.Name, v.BodySHA256)
		}
	}
	if got := SHA256Hex([]byte("hello")); got != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256(hello) = %s", got)
	}
	if EmptyBodySHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty body digest = %s", EmptyBodySHA256)
	}
}

// TestEveryCoveredFieldMatters is S2 at the string level: changing any field
// changes the bytes, which is what makes a signature over them bind that
// field. A field silently dropped from the builder fails here.
func TestEveryCoveredFieldMatters(t *testing.T) {
	base := Request{
		Method: "POST", Scheme: "https", Host: "aivan-hud.home.arpa",
		Target: "/admin?id=1", BodySHA256: SHA256Hex([]byte("good")),
		Nonce: "N1", Timestamp: "1700000000",
	}
	original := Canonical(base)

	changes := map[string]func(*Request){
		"method":     func(r *Request) { r.Method = "PUT" },
		"scheme":     func(r *Request) { r.Scheme = "http" },
		"host":       func(r *Request) { r.Host = "other.home.arpa" },
		"target":     func(r *Request) { r.Target = "/admin?id=2" },
		"body":       func(r *Request) { r.BodySHA256 = SHA256Hex([]byte("evil")) },
		"nonce":      func(r *Request) { r.Nonce = "N2" },
		"timestamp":  func(r *Request) { r.Timestamp = "1700000001" },
		"empty body": func(r *Request) { r.BodySHA256 = EmptyBodySHA256 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := base
			change(&r)
			if got := Canonical(r); got == original {
				t.Fatalf("changing %s left the canonical string unchanged", name)
			}
		})
	}
}

// TestQueryStringIsCovered is S19 at the string level: a signature over the
// path cannot authorize a different query string, because the target including
// the query is signed.
func TestQueryStringIsCovered(t *testing.T) {
	a := Request{Method: "GET", Scheme: "https", Host: "h.example", Target: "/item?id=1",
		BodySHA256: EmptyBodySHA256, Nonce: "N", Timestamp: "1"}
	b := a
	b.Target = "/item?id=2"
	if Canonical(a) == Canonical(b) {
		t.Fatal("two query strings produced the same canonical string")
	}
}

// TestCanonicalShape pins the literal shape of the string: a version line, six
// separators, and no trailing newline. This is what the browser must reproduce.
func TestCanonicalShape(t *testing.T) {
	got := Canonical(Request{
		Method: "GET", Scheme: "https", Host: "h.example", Target: "/",
		BodySHA256: EmptyBodySHA256, Nonce: "N", Timestamp: "1700000000",
	})
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("canonical string ends with a newline: %q", got)
	}
	lines := strings.Split(got, "\n")
	if len(lines) != 7 {
		t.Fatalf("got %d lines, want 7: %q", len(lines), got)
	}
	want := []string{"aivan-v1", "GET", "https://h.example", "/", EmptyBodySHA256, "N", "1700000000"}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"aivan-hud.home.arpa":      "aivan-hud.home.arpa",
		"AIVAN-HUD.home.arpa":      "aivan-hud.home.arpa",
		"aivan-hud.home.arpa:443":  "aivan-hud.home.arpa",
		"AIVAN-HUD.HOME.ARPA:8443": "aivan-hud.home.arpa",
		"[::1]:8080":               "[::1]",
		"[::1]":                    "[::1]",
		"":                         "",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPath(t *testing.T) {
	cases := map[string]string{
		"/":                 "/",
		"/admin":            "/admin",
		"/admin?":           "/admin",
		"/admin?id=1&x=%2F": "/admin",
		"/a%20b":            "/a%20b",
	}
	for in, want := range cases {
		if got := Path(in); got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDeviceIDRoundTrip(t *testing.T) {
	const canonical = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	id, err := ParseDeviceID(canonical)
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	if got := FormatDeviceID(id); got != canonical {
		t.Fatalf("FormatDeviceID = %q, want %q", got, canonical)
	}
}

// TestParseDeviceIDRefusesOtherSpellings keeps one id to one string: a device
// cannot present a second accepted form of its own id.
func TestParseDeviceIDRefusesOtherSpellings(t *testing.T) {
	bad := []string{
		"",
		"3f2504e04f8941d39a0c0305e82c3301",       // no dashes
		"3F2504E0-4F89-41D3-9A0C-0305E82C3301",   // uppercase
		"{3f2504e0-4f89-41d3-9a0c-0305e82c3301}", // braces
		"3f2504e0-4f89-41d3-9a0c-0305e82c330",    // short
		"3f2504e0-4f89-41d3-9a0c-0305e82c33011",  // long
		"3f2504e0x4f89-41d3-9a0c-0305e82c3301",   // wrong separator
		"3f2504e0-4f89-41d3-9a0c-0305e82c33zz",   // non-hex
	}
	for _, s := range bad {
		if _, err := ParseDeviceID(s); err == nil {
			t.Errorf("ParseDeviceID(%q) accepted a non-canonical spelling", s)
		}
	}
}

func TestParseTimestamp(t *testing.T) {
	if ts, err := ParseTimestamp("1700000000"); err != nil || ts != 1700000000 {
		t.Fatalf("ParseTimestamp = %d, %v", ts, err)
	}
	for _, s := range []string{"", "-1", "1.5", "0x10", " 1", "99999999999999999999", "+1"} {
		if _, err := ParseTimestamp(s); err == nil {
			t.Errorf("ParseTimestamp(%q) accepted a malformed timestamp", s)
		}
	}
}
