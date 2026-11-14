package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// quietGate is a Gate with the parts these tests need and nothing else. New
// always supplies a logger; the tests that build a Gate directly have to as
// well, or a refusal panics on the log line instead of answering.
func quietGate() *Gate {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return &Gate{log: log, decide: decisionLogger{log: log}}
}

// TestVerifySignatureRefusesWrongMethod pins the method. The endpoint takes a
// body, so a GET is not a request it can answer.
func TestVerifySignatureRefusesWrongMethod(t *testing.T) {
	g := quietGate()
	req := httptest.NewRequest(http.MethodGet, VerifySignaturePath, nil)
	w := httptest.NewRecorder()
	g.VerifySignature(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
	if got := w.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", got)
	}
}

// TestVerifySignatureRefusesMalformedBodies covers the shapes that must never
// reach a database read: bad JSON, unknown fields, trailing data, bad base64,
// and a purpose that does not name one principal.
func TestVerifySignatureRefusesMalformedBodies(t *testing.T) {
	g := quietGate()
	device := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	approval := "8f2504e0-4f89-41d3-9a0c-0305e82c3302"
	body := base64.StdEncoding.EncodeToString([]byte("aivan-approval-decision-v1\nid\nhash\napprove"))
	sig := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))

	cases := []struct {
		name string
		body string
	}{
		{"not json", `{`},
		{"empty object", `{}`},
		{"unknown field", `{"purpose":"request","body":"` + body + `","sig":"` + sig + `","extra":1}`},
		{"trailing data", `{"purpose":"request","body":"` + body + `","sig":"` + sig + `"}{}`},
		{"bad body base64", `{"purpose":"request","service":"` + device + `","body":"!!!","sig":"` + sig + `"}`},
		{"bad sig base64", `{"purpose":"request","service":"` + device + `","body":"` + body + `","sig":"!!!"}`},
		{"no purpose", `{"service":"` + device + `","body":"` + body + `","sig":"` + sig + `"}`},
		{"unknown purpose", `{"purpose":"grant","service":"` + device + `","body":"` + body + `","sig":"` + sig + `"}`},
		{"request naming a device", `{"purpose":"request","service":"` + device + `","device":"` + device + `","body":"` + body + `","sig":"` + sig + `"}`},
		{"approval naming a service", `{"purpose":"approval","device":"` + device + `","service":"` + device + `","approval":"` + approval + `","body":"` + body + `","sig":"` + sig + `"}`},
		{"approval with no approval id", `{"purpose":"approval","device":"` + device + `","body":"` + body + `","sig":"` + sig + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, VerifySignaturePath, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			g.VerifySignature(w, req)

			// Every malformed shape is the constant 401, so a caller cannot
			// learn which part of its request was wrong (S14).
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, http.StatusUnauthorized, w.Body.String())
			}
			if w.Body.Len() != 0 {
				t.Fatalf("refusal carried a body: %q", w.Body.String())
			}
		})
	}
}

// TestVerifySignatureBodyLimit pins the cap: a body larger than the limit is
// refused rather than read.
func TestVerifySignatureBodyLimit(t *testing.T) {
	g := quietGate()
	huge := strings.Repeat("a", verifySignatureBodyLimit+1)
	req := httptest.NewRequest(http.MethodPost, VerifySignaturePath, strings.NewReader(huge))
	w := httptest.NewRecorder()
	g.VerifySignature(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestThirdLineIsTheSignedRequestHash pins the field the approval check reads.
// The decision string is version, approval id, request hash, decision, device,
// seconds, expiry; a change to that order would make this endpoint verify a
// different line than the one the application signed.
func TestThirdLineIsTheSignedRequestHash(t *testing.T) {
	body := "aivan-approval-decision-v1\napproval-id\nabc123\napprove\ndevice\n3600\n2026-11-14T12:00:00Z"
	got, ok := thirdLine([]byte(body))
	if !ok {
		t.Fatal("thirdLine found no third line")
	}
	if got != "abc123" {
		t.Fatalf("thirdLine = %q, want abc123", got)
	}

	if _, ok := thirdLine([]byte("only\ntwo\n")); ok {
		t.Fatal("thirdLine found a third line in a two-line string")
	}
}

// TestVerifySignatureClaimsCarryNoAuthority pins the response shape: claims
// name the principal and its owner, and nothing that could be read as a
// permission.
func TestVerifySignatureClaimsCarryNoAuthority(t *testing.T) {
	w := httptest.NewRecorder()
	g := quietGate()
	g.writeSignatureClaims(w, verifySignatureResponse{Kind: "device", UserID: 42, DeviceID: "d1"})

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	want := map[string]bool{"kind": true, "user_id": true, "device_id": true}
	for key := range got {
		if !want[key] {
			t.Errorf("claims carry %q, which is not a claim this endpoint may make", key)
		}
	}
	if got["kind"] != "device" {
		t.Errorf("kind = %v, want device", got["kind"])
	}
}
