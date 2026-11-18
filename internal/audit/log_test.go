package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestReasonsAreLiterals is the mechanism behind "a reason code is a constant
// from a closed set". Each declared value is compared to what its own constant
// name says, so a future change that builds one from request data — a header,
// an error, a fmt.Sprintf — fails here rather than in production. A value that
// is interpolated cannot also be equal to the literal this test spells out.
func TestReasonsAreLiterals(t *testing.T) {
	// The table is written out by hand, independent of the declaration, so the
	// two have to agree.
	want := map[Reason]string{
		NoProof:                "no_proof",
		MalformedProof:         "malformed_proof",
		NonceUnknown:           "nonce_unknown",
		NonceExpired:           "nonce_expired",
		Replay:                 "replay",
		TimestampSkewed:        "timestamp_skewed",
		TimestampBefore:        "timestamp_before_issued",
		OriginMismatch:         "origin_mismatch",
		DeviceRevoked:          "device_revoked",
		UserInactive:           "user_inactive",
		BadSignature:           "bad_signature",
		AlgUnsupported:         "alg_unsupported",
		RoleInsufficient:       "role_insufficient",
		DevicePending:          "device_pending",
		DeviceKindInsufficient: "device_kind_insufficient",
		Username:               "username_unrepresentable",
		HostUnknown:            "host_unknown",
		ClassDefaulted:         "class_defaulted",
		PlainHTTP:              "plain_http",
		BodyTooLarge:           "body_too_large",
		Database:               "database_error",
		RateLimited:            "rate_limited",
		NonceTableFull:         "nonce_table_full",
		MethodNotAllowed:       "method_not_allowed",
		ForwardedMissing:       "forwarded_missing",
		BadRequest:             "bad_request",

		SessionInvalid: "session_invalid",
		SessionRefused: "session_refused",
		Logout:         "logout",
		CSRFMissing:    "csrf_missing",
		CSRFSite:       "csrf_samesite",
		PublicRoute:    "public_route",

		EnrollClaimed:   "claimed",
		EnrollRefused:   "enroll_refused",
		EnrollDuplicate: "enroll_duplicate",
		EnrollExpired:   "enroll_expired",
		EnrollCode:      "enroll_bad_code",
		EnrollOrigin:    "enroll_wrong_origin",

		Unknown: "unknown",
	}

	all := All()
	if len(all) != len(want) {
		t.Fatalf("All() has %d reasons, the test table has %d; one was added without a literal here",
			len(all), len(want))
	}
	for _, r := range all {
		literal, ok := want[r]
		if !ok {
			t.Errorf("reason %q is not covered by the literal table", r)
			continue
		}
		if string(r) != literal {
			t.Errorf("reason = %q, want the literal %q", r, literal)
		}
	}
	for r := range want {
		if !Valid(r) {
			t.Errorf("Valid(%q) = false, want true", r)
		}
	}
}

// TestNoReasonLooksLikeAHeader: a reason code is a word this service chose, so
// none of them can carry the shape of the values a request brings. This is the
// property that makes an accidental interpolation fail rather than publish a
// signature.
func TestNoReasonLooksLikeAHeader(t *testing.T) {
	for _, r := range All() {
		s := string(r)
		if strings.ContainsAny(s, " \t\r\n:=/") {
			t.Errorf("reason %q contains a character a header value would", s)
		}
		if len(s) == 0 || len(s) > 40 {
			t.Errorf("reason %q is not a short identifier", s)
		}
	}
}

// TestOrUnknown: a value outside the set is replaced, so the log cannot carry
// whatever a future caller interpolated.
func TestOrUnknown(t *testing.T) {
	if got := OrUnknown(NoProof); got != NoProof {
		t.Errorf("OrUnknown(no_proof) = %q", got)
	}
	for _, bad := range []Reason{"", "x", Reason("deadbeef0123456789abcdef"), Reason("no_proof ")} {
		if got := OrUnknown(bad); got != Unknown {
			t.Errorf("OrUnknown(%q) = %q, want unknown", bad, got)
		}
	}
}

// TestDeniedKeys is the deny list, including the near misses that must survive:
// a purge count keyed "sessions" is useful, and "sessions" is not a secret.
func TestDeniedKeys(t *testing.T) {
	for _, key := range []string{
		"cookie", "Cookie", "Set-Cookie", "nonce", "X-Aivan-Nonce",
		"signature", "X-Aivan-Signature", "sig",
		"dsn", "database_url", "password", "db_password",
		"token", "session_token", "authorization", "Authorization",
		"public_key", "private_key", "secret", "credential",
	} {
		if !deniedKey(key) {
			t.Errorf("deniedKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{
		"request_id", "device_id", "host", "method", "route", "status",
		"reason", "decision", "user_id", "nonces", "sessions", "error",
		"idle_expires_at", "listen", "policy", "hosts", "note",
	} {
		if deniedKey(key) {
			t.Errorf("deniedKey(%q) = true, want false", key)
		}
	}
}

// TestHandlerDropsSecrets drives a record through the handler the shipped
// logger uses and asserts the secret values are absent from the output while
// the useful fields survive.
func TestHandlerDropsSecrets(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&buf, nil)))

	const (
		sig     = "c2lnbmF0dXJlLXNlY3JldA"
		nonce   = "bm9uY2Utc2VjcmV0"
		cookie  = "c2Vzc2lvbi1zZWNyZXQ"
		dsn     = "postgres://aivan_authz:hunter2@db.internal:5432/aivan_core"
		keyText = "cHVibGljLWtleS1ieXRlcw"
	)
	log.Info("mixed",
		"request_id", "abc",
		"route", "/admin",
		"cookie", cookie,
		"nonce", nonce,
		"signature", sig,
		"X-Aivan-Signature", sig,
		"dsn", dsn,
		"public_key", keyText,
		"password", "hunter2",
		"error", "some useful text",
	)

	out := buf.String()
	for name, secret := range map[string]string{
		"signature":   sig,
		"nonce":       nonce,
		"cookie":      cookie,
		"dsn":         dsn,
		"public key":  keyText,
		"password":    "hunter2",
		"password in": "hunter2",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s reached the log: %s", name, out)
		}
	}
	for _, keep := range []string{"request_id", "route", "/admin", "error"} {
		if !strings.Contains(out, keep) {
			t.Errorf("log lost %q: %s", keep, out)
		}
	}

	// And the line is still one JSON object, which is what an operator's log
	// pipeline expects.
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, out)
	}
}

// TestHandlerFiltersGroups: a secret one group down is still a secret.
func TestHandlerFiltersGroups(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&buf, nil)))
	log.Info("group", slog.Group("proof", "nonce", "bm9uY2U", "device", "d-1"))

	out := buf.String()
	if strings.Contains(out, "bm9uY2U") {
		t.Fatalf("grouped nonce reached the log: %s", out)
	}
	if !strings.Contains(out, "d-1") {
		t.Fatalf("grouped device id was dropped: %s", out)
	}
}

// TestHandlerFiltersBoundAttributes: WithAttrs is the path a careless
// log.With("cookie", v) takes, and it must be filtered before binding.
func TestHandlerFiltersBoundAttributes(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&buf, nil))).With("cookie", "c2Vzc2lvbg", "route", "/admin")
	log.Info("bound")

	out := buf.String()
	if strings.Contains(out, "c2Vzc2lvbg") {
		t.Fatalf("bound cookie reached the log: %s", out)
	}
	if !strings.Contains(out, "/admin") {
		t.Fatalf("bound route was dropped: %s", out)
	}
}

// TestErrorNamesSQLStateNotTheDSN: a pgx error can carry the connection string
// in its message. The description must publish SQLSTATE and the server's own
// text instead.
func TestErrorNamesSQLStateNotTheDSN(t *testing.T) {
	const dsn = "postgres://aivan_authz:hunter2@db.internal:5432/aivan_core"
	pgErr := &pgconn.PgError{
		Code:    "42P01",
		Message: `relation "authz.devices" does not exist`,
	}
	// A pgx connect failure embeds the DSN in its own message.
	wrapped := fmt.Errorf("failed to connect to `%s`: %w", dsn, pgErr)

	got := Error(wrapped)
	if strings.Contains(got, dsn) || strings.Contains(got, "hunter2") {
		t.Fatalf("Error() leaked the DSN: %q", got)
	}
	if !strings.Contains(got, "42P01") {
		t.Errorf("Error() = %q, want it to name SQLSTATE 42P01", got)
	}
	if !strings.Contains(got, "does not exist") {
		t.Errorf("Error() = %q, want the server's short message", got)
	}

	// A non-pgx error that happens to carry a URL is scrubbed too.
	plain := errors.New("dial postgres://aivan_authz:hunter2@db.internal:5432/x failed")
	if got := Error(plain); strings.Contains(got, "hunter2") || strings.Contains(got, "db.internal") {
		t.Fatalf("Error() leaked a URL: %q", got)
	}
	if got := Error(nil); got != "" {
		t.Errorf("Error(nil) = %q, want empty", got)
	}
	if got := Error(fmt.Errorf("x: %w", context.DeadlineExceeded)); got != "timeout" {
		t.Errorf("Error(deadline) = %q, want timeout", got)
	}
}

// TestScrubRemovesPasswordForms covers the shapes pgx prints a credential in.
func TestScrubRemovesPasswordForms(t *testing.T) {
	for _, in := range []string{
		"password=hunter2 host=db",
		"password: hunter2 host=db",
		"aivan: password 'hunter2' rejected",
	} {
		if got := scrub(in); strings.Contains(got, "hunter2") {
			t.Errorf("scrub(%q) = %q, still carries the password", in, got)
		}
	}
}
