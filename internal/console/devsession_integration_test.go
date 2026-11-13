//go:build devtools && integration

package console_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// TestDevSessionMintsAReadableCookie is the Phase E affordance's own test: the
// command prints a cookie the gate's session read path accepts, and the row it
// writes is the one that path reads.
func TestDevSessionMintsAReadableCookie(t *testing.T) {
	f := setup(t)
	// The shared fixture already holds a device of this kind for alice; this
	// test is about a fresh mint, not about the partial unique index.
	clearDevices(t, f)

	res, err := console.MintDevSession(context.Background(), f.pool, console.DevSessionOptions{
		Username: "alice",
		Origin:   "aivan-hud.home.arpa",
		Kind:     "browser",
		Name:     "console test",
	})
	if err != nil {
		t.Fatalf("MintDevSession: %v", err)
	}
	if res.UserID != 1 || res.Username != "alice" {
		t.Errorf("user = %d/%q, want 1/alice", res.UserID, res.Username)
	}
	if !strings.HasPrefix(res.Cookie, gate.SessionCookie+"=") {
		t.Errorf("cookie %q does not name %s", res.Cookie, gate.SessionCookie)
	}
	// The attribute set is the mint endpoint's, because the console calls the
	// same constant. A change to one must not leave the other behind.
	if !strings.HasSuffix(res.Cookie, "; Path=/; Secure; HttpOnly; SameSite=Lax") {
		t.Errorf("cookie attributes are not the mint's: %q", res.Cookie)
	}

	// The token in the cookie is the one the read path hashes.
	token := strings.TrimSuffix(strings.TrimPrefix(res.Cookie, gate.SessionCookie+"="),
		"; Path=/; Secure; HttpOnly; SameSite=Lax")
	var deviceID string
	if err := f.pool.QueryRow(context.Background(), `
select d.id::text
  from authz.sessions s
  join authz.devices d on d.id = s.device_id
 where s.token_hash = $1`, hashOf(t, token)).Scan(&deviceID); err != nil {
		t.Fatalf("session row for the printed cookie: %v", err)
	}
	if deviceID != res.DeviceID {
		t.Errorf("session is bound to %s, want %s", deviceID, res.DeviceID)
	}

	// The printed block is shaped so `grep Set-Cookie | cut -d' ' -f2` yields
	// the cookie value.
	var out bytes.Buffer
	if err := console.WriteDevSession(&out, res); err != nil {
		t.Fatalf("WriteDevSession: %v", err)
	}
	line, _, ok := strings.Cut(out.String(), "\n")
	if !ok || line != "Set-Cookie: "+res.Cookie {
		t.Errorf("first line = %q, want the Set-Cookie line", line)
	}
}

// TestDevSessionRefusesAnUnknownUser keeps a typo a console error rather than a
// device row attached to nobody.
func TestDevSessionRefusesAnUnknownUser(t *testing.T) {
	f := setup(t)
	_, err := console.MintDevSession(context.Background(), f.pool, console.DevSessionOptions{
		Username: "nobody",
		Origin:   "aivan-hud.home.arpa",
	})
	if err == nil || !strings.Contains(err.Error(), "no active user") {
		t.Fatalf("err = %v, want a refusal naming the user", err)
	}
}

// TestDevSessionRefusesASecondDeviceOfOneKind documents the partial unique
// index's refusal, which is what a repeated test hits first.
func TestDevSessionRefusesASecondDeviceOfOneKind(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	opts := console.DevSessionOptions{Username: "alice", Origin: "aivan-hud.home.arpa", Kind: "browser"}
	if _, err := console.MintDevSession(context.Background(), f.pool, opts); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	_, err := console.MintDevSession(context.Background(), f.pool, opts)
	if err == nil || !strings.Contains(err.Error(), "authz list-devices") {
		t.Fatalf("err = %v, want a refusal naming list-devices", err)
	}
}

// TestDevSessionRefusesAnInactiveUser keeps a deactivated person from being
// handed a fresh cookie by the console.
func TestDevSessionRefusesAnInactiveUser(t *testing.T) {
	f := setup(t)
	harness.Exec(t, f.super, `
		insert into public.users (id, email, username, active) values (9, 'off@example.invalid', 'off', false)
	`)
	_, err := console.MintDevSession(context.Background(), f.pool, console.DevSessionOptions{
		Username: "off",
		Origin:   "aivan-hud.home.arpa",
	})
	if err == nil || !strings.Contains(err.Error(), "no active user") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

// clearDevices removes the shared fixture's devices, so a test that mints one
// of its own is not refused by the partial unique index.
func clearDevices(t *testing.T, f fixture) {
	t.Helper()
	harness.Exec(t, f.super, `delete from authz.sessions; delete from authz.devices;`)
}

// hashOf is the digest the session read path looks up.
func hashOf(t *testing.T, token string) []byte {
	t.Helper()
	sum := proof.SHA256Sum([]byte(token))
	return sum[:]
}
