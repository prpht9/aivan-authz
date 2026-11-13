package gate

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSRFRefusal pins the rule table without a database: which methods and
// which header combinations pass.
func TestCSRFRefusal(t *testing.T) {
	cases := []struct {
		name   string
		method string
		site   string
		csrf   string
		want   Reason
	}{
		{"GET is always safe", http.MethodGet, "", "", ""},
		{"HEAD is always safe", http.MethodHead, "cross-site", "", ""},
		{"OPTIONS is always safe", http.MethodOptions, "same-site", "", ""},
		{"POST same-origin", http.MethodPost, "same-origin", "", ""},
		{"POST none", http.MethodPost, "none", "", ""},
		{"POST same-site", http.MethodPost, "same-site", "", ReasonCSRFSite},
		{"POST cross-site", http.MethodPost, "cross-site", "", ReasonCSRFMissing},
		{"POST with no header", http.MethodPost, "", "", ReasonCSRFMissing},
		{"POST with a token", http.MethodPost, "", strings.Repeat("A", 16), ""},
		{"POST with a token and same-site", http.MethodPost, "same-site", strings.Repeat("A", 16), ReasonCSRFSite},
		{"PUT with a token", http.MethodPut, "", strings.Repeat("-", 128), ""},
		{"DELETE with a token", http.MethodDelete, "", strings.Repeat("_", 16), ""},
		{"PATCH without a token", http.MethodPatch, "", "", ReasonCSRFMissing},
		{"POST with a short token", http.MethodPost, "", strings.Repeat("A", 15), ReasonCSRFMissing},
		{"POST with a long token", http.MethodPost, "", strings.Repeat("A", 129), ReasonCSRFMissing},
		{"POST with a token that is not base64url", http.MethodPost, "", strings.Repeat("A", 20) + "!", ReasonCSRFMissing},
		{"POST with a token containing a space", http.MethodPost, "", strings.Repeat("A", 16) + " ", ReasonCSRFMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/__aivan/verify", nil)
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if tc.csrf != "" {
				req.Header.Set(HeaderCSRF, tc.csrf)
			}
			if got := csrfRefusal(req, tc.method); got != tc.want {
				t.Fatalf("csrfRefusal = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestValidCSRFTokenBoundaries checks the two ends of the length rule and the
// character class, which is what the regex in the spec says.
func TestValidCSRFTokenBoundaries(t *testing.T) {
	if validCSRFToken(strings.Repeat("a", 15)) {
		t.Error("15 characters was accepted")
	}
	if !validCSRFToken(strings.Repeat("a", 16)) {
		t.Error("16 characters was refused")
	}
	if !validCSRFToken(strings.Repeat("a", 128)) {
		t.Error("128 characters was refused")
	}
	if validCSRFToken(strings.Repeat("a", 129)) {
		t.Error("129 characters was accepted")
	}
	for _, v := range []string{"abcdef0123456789", "ABCDEF0123456789", "________--------", "a_b-c_2345678901"} {
		if !validCSRFToken(v) {
			t.Errorf("%q was refused", v)
		}
	}
	for _, v := range []string{"abcdef012345678!", "abcdef012345678 ", "abcdef012345678.", "abcdef0123456789="} {
		if validCSRFToken(v) {
			t.Errorf("%q was accepted", v)
		}
	}
}

// TestSessionCookieShape asserts a cookie value could have come from a mint.
func TestSessionCookieShape(t *testing.T) {
	raw := make([]byte, sessionTokenBytes)
	for i := range raw {
		raw[i] = byte(i)
	}
	good := base64.RawURLEncoding.EncodeToString(raw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: good})
	if got, ok := sessionToken(req); !ok || got != good {
		t.Fatalf("sessionToken = %q, %v; want the minted value", got, ok)
	}

	bad := []string{
		"",
		"short",
		good[:42],               // one byte short
		good + "A",              // one byte long
		strings.Repeat("=", 43), // padding, which base64url without padding refuses
		good[:42] + "+",         // a character base64url does not use
	}
	// A well-formed token that matches no row is not refused here: it is a
	// syntactically valid credential whose lookup finds nothing, which the
	// integration tests cover. The shape check only rejects values a mint
	// could never have produced.
	for _, v := range bad {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: v})
		if _, ok := sessionToken(req); ok {
			t.Errorf("sessionToken accepted %q", v)
		}
	}

	// A cookie under another name is not the session cookie.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "aivan_session", Value: good})
	if _, ok := sessionToken(req); ok {
		t.Error("the unprefixed cookie name was accepted")
	}
}

// TestAnyProofHeader: one proof header is enough to be on the proof path,
// which is what makes a half-sent proof a refusal rather than a cookie
// fallback.
func TestAnyProofHeader(t *testing.T) {
	none := httptest.NewRequest(http.MethodGet, "/", nil)
	if anyProofHeader(none) {
		t.Error("a request with no proof headers was treated as a proof")
	}
	for _, name := range []string{HeaderDevice, HeaderNonce, HeaderSignature, HeaderTimestamp} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(name, "x")
		if !anyProofHeader(req) {
			t.Errorf("%s alone was not recognised as a proof header", name)
		}
	}
}
