//go:build integration

package main_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/servicekey"
	"github.com/chris/aivan-authz/test/harness"
)

// relayRecorder is a stand-in for aivan-approval: it verifies a registration the
// way `Relay::Auth` does — the name resolves to a key, and the signature covers
// the exact bytes the handler received — and remembers what arrived.
//
// It is not a second implementation of the relay. It exists to prove the two
// things this tool is responsible for: that it signs what it sends, and that it
// sends the device the home actually created.
type relayRecorder struct {
	t   *testing.T
	key ed25519.PublicKey

	mu       sync.Mutex
	body     []byte
	verb     string
	path     string
	requests int
}

func (r *relayRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		r.t.Errorf("relay: read body: %v", err)
	}
	r.mu.Lock()
	r.body, r.verb, r.path = raw, req.Method, req.URL.Path
	r.requests++
	r.mu.Unlock()

	if got := req.Header.Get("X-Aivan-Service"); got != servicekey.DefaultName {
		r.t.Errorf("X-Aivan-Service = %q, want %q", got, servicekey.DefaultName)
	}
	sig, err := base64.StdEncoding.DecodeString(req.Header.Get("X-Aivan-Signature"))
	if err != nil {
		r.t.Errorf("X-Aivan-Signature is not base64: %v", err)
	} else if !ed25519.Verify(r.key, raw, sig) {
		r.t.Errorf("signature does not verify over the bytes received: %q", raw)
	}

	w.Header().Set("Content-Type", "application/json")
	if req.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, registrationEcho(raw))
}

func (r *relayRecorder) snapshot() (body []byte, verb, path string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body, r.verb, r.path, r.requests
}

// deviceIDFromBody reads the id a registration named, so the fake answers with
// the row the home created rather than a fixture.
func deviceIDFromBody(raw []byte) string {
	var sent struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(raw, &sent)
	return sent.DeviceID
}

// registrationEcho answers the way `Relay::Devices.register` does: with the row
// it just wrote, which repeats the algorithm the caller sent rather than one of
// the fake's own choosing.
func registrationEcho(raw []byte) string {
	var sent struct {
		DeviceID string `json:"device_id"`
		UserID   string `json:"user_id"`
		Alg      string `json:"alg"`
		Kind     string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &sent); err != nil {
		return `{"error":"unreadable"}`
	}
	return fmt.Sprintf(`{"id":%q,"user_id":%q,"alg":%q,"kind":%q,"state":"live"}`,
		sent.DeviceID, sent.UserID, sent.Alg, sent.Kind)
}

// writeRelayKey writes a service key pair into dir and returns the recorder that
// verifies with its public half.
func writeRelayKey(t *testing.T, dir string) (*relayRecorder, *servicekey.KeyPair) {
	t.Helper()
	_, key, err := servicekey.Generate(dir, servicekey.DefaultName)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &relayRecorder{t: t, key: key.Public}, key
}

// startRelay serves a recorder and returns its URL.
func startRelay(t *testing.T, r *relayRecorder) string {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv.URL
}

// claimDevice inserts the device a claim would produce and marks the record
// claimed, which is the state the phone leaves behind.
//
// It writes the row as the operator credential because the gate's own claim path
// needs a signature from a key the phone holds; the command under test reads the
// record's claimed_device_id and nothing else, so the row's origin is irrelevant
// to what is being proven.
//
// The key is P-256 and the algorithm es256, because that is what an Android
// Keystore produces and therefore what every phone row holds. A fixture that
// wrote an Ed25519 device passed while the real path failed.
func claimDevice(t *testing.T, super, recordID, username, kind string) (deviceID string, publicKey []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, super)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if err := conn.QueryRow(ctx, `
with user_row as (
  select id from public.users where username = $1
), new_device as (
  insert into authz.devices (id, user_id, origin, name, kind, public_key, alg, state)
  select gen_random_uuid(), user_row.id, 'aivan-hud.home.arpa', 'enrolled ' || $2, $2, $3, 'es256', 'live'
    from user_row
  returning id
)
update authz.pending_enrollments
   set claimed_at = now(), claimed_device_id = (select id from new_device)
 where id = $4
returning claimed_device_id::text`,
		username, kind, pub, recordID).Scan(&deviceID); err != nil {
		t.Fatalf("claim record: %v", err)
	}
	return deviceID, pub
}

// TestEnrollNewRegisterRelayRegistersTheClaimedDevice is the bundled flow end to
// end: the real binary mints a code, the phone's claim is simulated by writing
// the row a claim produces, and the tool registers that device with the relay
// under the service key it holds.
func TestEnrollNewRegisterRelayRegistersTheClaimedDevice(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	dir := t.TempDir()
	recorder, _ := writeRelayKey(t, dir)
	relayURL := startRelay(t, recorder)

	env := append(enrollEnv(t, harness.Operator(t, super)),
		"AIVAN_APPROVAL_URL="+relayURL,
	)

	// The command waits for a claim, so it runs in the background while the
	// test claims the record the way a phone would.
	cmd := exec.Command(binary(t),
		"enroll-new", "--username", "alice", "--origin", "aivan-hud.home.arpa",
		"--kind", "phone", "--qr", "none", "--register-relay",
		"--dir", dir)
	cmd.Env = env
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// A failure must not leave a process behind for the rest of the suite.
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	recordID := waitForPendingRecord(t, super, "alice", "phone")
	deviceID, publicKey := claimDevice(t, super, recordID, "alice", "phone")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("enroll-new --register-relay: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the command did not finish after the claim; output:\n%s", out.String())
	}

	if !strings.Contains(out.String(), "Registered with the relay: device "+deviceID) {
		t.Errorf("output does not name the registered device:\n%s", out.String())
	}

	body, verb, path, n := recorder.snapshot()
	if n != 1 {
		t.Fatalf("the relay saw %d requests, want 1", n)
	}
	if verb != http.MethodPost || path != "/devices" {
		t.Errorf("relay saw %s %s, want POST /devices", verb, path)
	}

	var sent map[string]string
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if sent["device_id"] != deviceID {
		t.Errorf("registered device_id = %q, want the claimed row %q", sent["device_id"], deviceID)
	}
	if sent["user_id"] != "1" {
		t.Errorf("registered user_id = %q, want 1", sent["user_id"])
	}
	if sent["kind"] != "phone" || sent["alg"] != "es256" {
		t.Errorf("registered kind/alg = %q/%q, want phone/es256", sent["kind"], sent["alg"])
	}
	decoded, err := base64.StdEncoding.DecodeString(sent["public_key"])
	if err != nil {
		t.Fatalf("registered public_key is not base64: %v", err)
	}
	if string(decoded) != string(publicKey) {
		t.Error("the registered public key is not the key the device row holds")
	}
}

// waitForPendingRecord returns the id of the live record a command just minted.
func waitForPendingRecord(t *testing.T, super, username, kind string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var id string
		err := connectScan(t, super, `
select pe.id::text
  from authz.pending_enrollments pe
  join public.users u on u.id = pe.user_id
 where u.username = $1 and pe.kind = $2 and pe.claimed_at is null
 order by pe.created_at desc limit 1`, []any{username, kind}, &id)
		if err == nil && id != "" {
			return id
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read pending record: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no pending %s record for %q appeared", kind, username)
	return ""
}

// TestRelayRegisterRegistersAnEnrolledDevice covers the second half on its own:
// the device exists, the relay was down when it was enrolled, and the operator
// runs the registration later.
func TestRelayRegisterRegistersAnEnrolledDevice(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	dir := t.TempDir()
	recorder, _ := writeRelayKey(t, dir)
	relayURL := startRelay(t, recorder)

	// A device and its live record, as a completed enrollment leaves them.
	recordID := insertPendingRecord(t, super, "alice", "phone")
	deviceID, publicKey := claimDevice(t, super, recordID, "alice", "phone")

	code, out := runConsole(t,
		append(enrollEnv(t, harness.Operator(t, super)), "AIVAN_APPROVAL_URL="+relayURL),
		"relay-register", "--device", deviceID, "--dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, deviceID) {
		t.Errorf("output does not name the device:\n%s", out)
	}

	body, _, _, n := recorder.snapshot()
	if n != 1 {
		t.Fatalf("the relay saw %d requests, want 1", n)
	}
	var sent map[string]string
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if sent["device_id"] != deviceID {
		t.Errorf("registered device_id = %q, want %q", sent["device_id"], deviceID)
	}
	if decoded, _ := base64.StdEncoding.DecodeString(sent["public_key"]); string(decoded) != string(publicKey) {
		t.Error("the registered key is not the device row's key")
	}
}

// TestRelayRegisterRefusesANonRelayKind: a panel cannot sign a device proof, so a
// row for one at the relay would be a row nothing can use.
func TestRelayRegisterRefusesANonRelayKind(t *testing.T) {
	_, _, super := harness.Setup(t)
	seedOneUser(t, super, "alice")

	dir := t.TempDir()
	recorder, _ := writeRelayKey(t, dir)
	relayURL := startRelay(t, recorder)

	recordID := insertPendingRecord(t, super, "alice", "panel")
	deviceID, _ := claimDevice(t, super, recordID, "alice", "panel")

	code, out := runConsole(t,
		append(enrollEnv(t, harness.Operator(t, super)), "AIVAN_APPROVAL_URL="+relayURL),
		"relay-register", "--device", deviceID, "--dir", dir)
	if code == 0 {
		t.Fatalf("a panel was registered; output: %s", out)
	}
	if !strings.Contains(out, "the relay registers kinds") {
		t.Errorf("refusal does not name the relay's kinds:\n%s", out)
	}
	if _, _, _, n := recorder.snapshot(); n != 0 {
		t.Errorf("the refusal reached the network (%d requests)", n)
	}
}

// TestRelayRetireSignsAnEmptyBody: the relay revokes a row and answers 204.
func TestRelayRetireSignsAnEmptyBody(t *testing.T) {
	_, _, super := harness.Setup(t)
	dir := t.TempDir()
	recorder, _ := writeRelayKey(t, dir)
	relayURL := startRelay(t, recorder)

	deviceID := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	code, out := runConsole(t,
		append(enrollEnv(t, harness.Operator(t, super)), "AIVAN_APPROVAL_URL="+relayURL),
		"relay-retire", "--device", deviceID, "--dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}
	body, verb, path, _ := recorder.snapshot()
	if verb != http.MethodDelete || path != "/devices/"+deviceID {
		t.Errorf("relay saw %s %s, want DELETE /devices/%s", verb, path, deviceID)
	}
	if len(body) != 0 {
		t.Errorf("DELETE carried a body: %q", body)
	}
}

// TestRelayKeygenWritesAnIgnoredPair: the generated private half must not be
// something git would pick up, and the command must print the public half so an
// operator can carry it to the relay's host.
func TestRelayKeygenWritesAnIgnoredPair(t *testing.T) {
	dir := t.TempDir()
	code, out := runConsole(t, os.Environ(), "relay-keygen", "--dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d; output: %s", code, out)
	}
	if !strings.Contains(out, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("output does not print the public key:\n%s", out)
	}
	if strings.Contains(out, "-----BEGIN PRIVATE KEY-----") {
		t.Error("output printed the private key")
	}
	if !strings.Contains(out, "fingerprint:") {
		t.Errorf("output does not print a fingerprint:\n%s", out)
	}

	for name, mode := range map[string]os.FileMode{
		servicekey.DefaultName + ".key": 0o600,
		servicekey.DefaultName + ".pub": 0o644,
	} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %04o, want %04o", name, info.Mode().Perm(), mode)
		}
	}
}

// TestRelayCommandsRefuseAMissingKey names the fix: the first thing a new
// operator hits is no key at all.
func TestRelayCommandsRefuseAMissingKey(t *testing.T) {
	_, _, super := harness.Setup(t)
	code, out := runConsole(t, enrollEnv(t, harness.Operator(t, super)),
		"relay-register", "--device", "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "--dir", t.TempDir())
	if code == 0 {
		t.Fatalf("a missing key was accepted; output: %s", out)
	}
	if !strings.Contains(out, "relay-keygen") {
		t.Errorf("refusal does not name relay-keygen:\n%s", out)
	}
}

// insertPendingRecord writes the unclaimed record a mint leaves, so a test that
// needs only the post-claim half does not have to race a mint.
func insertPendingRecord(t *testing.T, super, username, kind string) string {
	t.Helper()
	var id string
	code := proof.SHA256Sum([]byte("unused-" + username + "-" + kind + time.Now().String()))
	if err := connectScan(t, super, `
insert into authz.pending_enrollments (user_id, origin, kind, code_hash, expires_at)
select u.id, 'aivan-hud.home.arpa', $2, $3, now() + interval '15 minutes'
  from public.users u where u.username = $1
returning id::text`, []any{username, kind, code[:]}, &id); err != nil {
		t.Fatalf("insert pending record: %v", err)
	}
	return id
}
