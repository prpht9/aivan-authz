//go:build integration

package main_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// running is a serve process under test with its stdout collected.
type running struct {
	addr string
	logs *lockedBuffer
	cmd  *exec.Cmd
	stop func()
}

// lockedBuffer collects the process's stdout across goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startServe runs `authz serve` against the environment's database, waits for
// its startup line, and returns the address it is listening on. The stop
// function sends SIGTERM and waits for a clean exit.
func startServe(t *testing.T, env []string) *running {
	t.Helper()

	cmd := exec.Command(binary(t), "serve")
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	logs := &lockedBuffer{}
	lines := make(chan string, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := bufio.NewScanner(stdout)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			line := s.Text()
			_, _ = logs.Write([]byte(line + "\n"))
			select {
			case lines <- line:
			default:
			}
		}
	}()
	var stderrBuf bytes.Buffer
	go func() { _, _ = io.Copy(&stderrBuf, stderr) }()

	addr := ""
	deadline := time.After(20 * time.Second)
	for addr == "" {
		select {
		case line := <-lines:
			var rec struct {
				Msg  string `json:"msg"`
				Addr string `json:"listen"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			if rec.Msg == "listening" {
				addr = rec.Addr
			}
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatalf("no startup line within 20s; stderr: %s", stderrBuf.String())
		}
	}

	stop := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
		}
		wg.Wait()
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			stop()
		}
	})
	return &running{addr: dialable(addr), logs: logs, cmd: cmd, stop: stop}
}

// serveEnvForUser is serveEnv plus one seeded person, for a test that needs a
// device to sign with.
func serveEnvForUser(t *testing.T, service, super, listen string) []string {
	t.Helper()
	harness.SeedUsers(t, super,
		[]harness.User{{ID: 1, Username: "alice", Active: true}},
		map[int64]string{10: "admin"},
		map[int64][]int64{10: {1}})
	return serveEnv(t, service, listen)
}

// deviceKey is a seeded device and the key that signs for it.
type deviceKey struct {
	ID   [16]byte
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// seedDevice inserts one ed25519 device for alice on the gated host.
func seedDevice(t *testing.T, super string) deviceKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("id: %v", err)
	}
	harness.Exec(t, super, fmt.Sprintf(`
		insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
		values ('%s', 1, 'aivan-hud.home.arpa', 'log probe', 'browser', decode('%x','hex'), 'ed25519')`,
		proof.FormatDeviceID(id), []byte(pub)))
	return deviceKey{ID: id, Pub: pub, Priv: priv}
}

// signRequest returns the four proof headers for a canonical request.
func signRequest(d deviceKey, method, target, body, nonce string, ts time.Time) map[string]string {
	canonical := proof.Canonical(proof.Request{
		Method:     method,
		Scheme:     "https",
		Host:       "aivan-hud.home.arpa",
		Target:     target,
		BodySHA256: proof.SHA256Hex([]byte(body)),
		Nonce:      nonce,
		Timestamp:  fmt.Sprintf("%d", ts.Unix()),
	})
	return map[string]string{
		gate.HeaderDevice:    proof.FormatDeviceID(d.ID),
		gate.HeaderNonce:     nonce,
		gate.HeaderTimestamp: fmt.Sprintf("%d", ts.Unix()),
		gate.HeaderSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(d.Priv, []byte(canonical))),
	}
}

// issueNonce asks the running process for a nonce.
func issueNonce(t *testing.T, base string, d deviceKey) string {
	t.Helper()
	body := fmt.Sprintf(`{"device":%q}`, proof.FormatDeviceID(d.ID))
	resp, err := http.Post(base+"/__aivan/nonce", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	return out.Nonce
}

// verify sends one forwardAuth-shaped request and returns status and headers.
func verify(t *testing.T, base, method, target, body string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/__aivan/verify", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "aivan-hud.home.arpa")
	req.Header.Set("X-Forwarded-Uri", target)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(raw)
}

// TestServeStartsWithoutPurging is the handover's deployment claim in §7: the
// gate starts, probes, and serves. It does not migrate and it does not purge, so
// expired scratch rows are still there after startup and the admin binary's
// CronJob is what removes them.
//
// The test would also catch a regression where the purge came back: a gate that
// deleted these rows would fail here.
func TestServeStartsWithoutPurging(t *testing.T) {
	service, super := harness.Setup(t)
	env := serveEnvForUser(t, service, super, "127.0.0.1:0")
	d := seedDevice(t, super)
	harness.Exec(t, super, fmt.Sprintf(`
		insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
		values (decode(repeat('ab',32),'hex'), '%s', now() - interval '3 hours', now() - interval '2 hours');
		insert into authz.sessions (token_hash, device_id, idle_expires_at, absolute_expires_at)
		values (decode(repeat('cd',32),'hex'), '%s', now() - interval '2 hours', now() - interval '1 hour')`,
		proof.FormatDeviceID(d.ID), proof.FormatDeviceID(d.ID)))

	proc := startServe(t, env)
	if code := waitForStatus(t, "http://"+proc.addr+"/healthz", http.StatusOK); code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}

	var nonces, sessions int
	conn := openConn(t, super)
	defer func() { _ = conn.Close(context.Background()) }()
	if err := conn.QueryRow(t.Context(),
		`select count(*) from authz.nonces where nonce_hash = decode(repeat('ab',32),'hex')`).Scan(&nonces); err != nil {
		t.Fatalf("count nonces: %v", err)
	}
	if err := conn.QueryRow(t.Context(),
		`select count(*) from authz.sessions where token_hash = decode(repeat('cd',32),'hex')`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if nonces != 1 {
		t.Errorf("expired nonce rows after startup = %d, want the row left for the CronJob", nonces)
	}
	if sessions != 1 {
		t.Errorf("expired session rows after startup = %d, want the row left for the CronJob", sessions)
	}

	if !strings.Contains(proc.logs.String(), `"msg":"listening"`) {
		t.Fatalf("no startup line:\n%s", proc.logs.String())
	}
	// The gate no longer has a purge to report.
	if strings.Contains(proc.logs.String(), `"purge"`) || strings.Contains(proc.logs.String(), `"purge_interval"`) {
		t.Errorf("the gate logged a purge:\n%s", proc.logs.String())
	}
}

// openConn opens a superuser connection for a direct read.
func openConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return conn
}

// TestServeLogCarriesNoSecrets is G3's acceptance: a request carrying a real
// signature, nonce and cookie is driven through every route, including the
// failure paths, and none of the three values appears anywhere in stdout.
//
// The gate logs at info in the shipped binary, so this asserts the shipped
// level. The registry test in package audit covers attribute filtering; this
// test covers what the handlers actually pass.
func TestServeLogCarriesNoSecrets(t *testing.T) {
	service, super := harness.Setup(t)
	env := serveEnvForUser(t, service, super, "127.0.0.1:0")
	d := seedDevice(t, super)

	proc := startServe(t, env)
	base := "http://" + proc.addr
	if code := waitForStatus(t, base+"/healthz", http.StatusOK); code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}

	// A nonce from the endpoint: its text is a secret the gate never logs.
	nonce := issueNonce(t, base, d)
	ts := time.Now()

	// A valid proof, then the same nonce replayed.
	headers := signRequest(d, http.MethodGet, "/dashboard", "", nonce, ts)
	if resp, body := verify(t, base, http.MethodGet, "/dashboard", "", headers); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid proof = %d %q, want 200", resp.StatusCode, body)
	}
	verify(t, base, http.MethodGet, "/dashboard", "", headers) // replay: 401

	// A bad signature over a live nonce.
	bad := signRequest(d, http.MethodGet, "/dashboard", "", issueNonce(t, base, d), ts)
	bad[gate.HeaderSignature] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	verify(t, base, http.MethodGet, "/dashboard", "", bad)

	// A malformed proof, and no proof at all.
	verify(t, base, http.MethodGet, "/dashboard", "", map[string]string{gate.HeaderDevice: "nope"})
	verify(t, base, http.MethodGet, "/dashboard", "", nil)

	// A mint, which produces the cookie.
	mintNonce := issueNonce(t, base, d)
	mintHeaders := signRequest(d, http.MethodPost, "/__aivan/session", "", mintNonce, ts)
	req, err := http.NewRequest(http.MethodPost, base+"/__aivan/session", nil)
	if err != nil {
		t.Fatalf("mint request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "aivan-hud.home.arpa")
	for k, v := range mintHeaders {
		req.Header.Set(k, v)
	}
	mintResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	mintResp.Body.Close()
	if mintResp.StatusCode != http.StatusNoContent {
		t.Fatalf("mint = %d, want 204", mintResp.StatusCode)
	}
	var cookie string
	for _, c := range mintResp.Cookies() {
		if c.Name == gate.SessionCookie {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("mint set no session cookie")
	}

	// A cookie-authenticated verify and a logout, which deletes the row.
	cookieReq, _ := http.NewRequest(http.MethodGet, base+"/__aivan/verify", nil)
	cookieReq.Header.Set("X-Forwarded-Method", http.MethodGet)
	cookieReq.Header.Set("X-Forwarded-Proto", "https")
	cookieReq.Header.Set("X-Forwarded-Host", "aivan-hud.home.arpa")
	cookieReq.Header.Set("X-Forwarded-Uri", "/dashboard")
	cookieReq.Header.Set("Cookie", gate.SessionCookie+"="+cookie)
	if resp, err := http.DefaultClient.Do(cookieReq); err != nil {
		t.Fatalf("cookie verify: %v", err)
	} else {
		resp.Body.Close()
	}
	logoutReq, _ := http.NewRequest(http.MethodDelete, base+"/__aivan/session", nil)
	logoutReq.Header.Set("Cookie", gate.SessionCookie+"="+cookie)
	if resp, err := http.DefaultClient.Do(logoutReq); err != nil {
		t.Fatalf("logout: %v", err)
	} else {
		resp.Body.Close()
	}

	// The enrollment page and a malformed claim.
	if resp, err := http.Get(base + "/__aivan/enroll"); err != nil {
		t.Fatalf("enroll page: %v", err)
	} else {
		resp.Body.Close()
	}
	claimBody := `{"code":"AAAA","kind":"browser","alg":"ed25519","public_key":"x","signature":"y"}`
	if resp, err := http.Post(base+"/__aivan/enroll", "application/json",
		strings.NewReader(claimBody)); err != nil {
		t.Fatalf("claim: %v", err)
	} else {
		resp.Body.Close()
	}

	// An oversized body, which is the 413 path.
	big := strings.Repeat("x", 2*1024*1024)
	bigHeaders := signRequest(d, http.MethodPost, "/dashboard", big, issueNonce(t, base, d), ts)
	verify(t, base, http.MethodPost, "/dashboard", big, bigHeaders)

	proc.stop()

	logs := proc.logs.String()
	if logs == "" {
		t.Fatal("the process logged nothing")
	}
	secrets := map[string]string{
		"the nonce":         nonce,
		"the mint nonce":    mintNonce,
		"the signature":     headers[gate.HeaderSignature],
		"the cookie":        cookie,
		"the bad signature": bad[gate.HeaderSignature],
	}
	for name, value := range secrets {
		if value == "" {
			continue
		}
		if strings.Contains(logs, value) {
			t.Errorf("%s reached stdout:\n%s", name, logs)
		}
	}
	// The whole log is one JSON object per line, which is what the JSON handler
	// promises and what an operator's pipeline reads.
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", line, err)
		}
	}
	// The decision lines are there, so the test is looking at a process that did
	// the work rather than one that logged nothing.
	if !strings.Contains(logs, `"msg":"decision"`) {
		t.Errorf("no decision lines in the log:\n%s", logs)
	}
}

// TestPolicyMaxBodyIsAtTheProxyCeiling pins the deployed numbers: the policy
// file must declare the proxy ceiling, and it must be above AIVAN_MAX_BODY, or
// the gate refuses to start. The k8s ConfigMap is the source of both values.
func TestPolicyMaxBodyIsAtTheProxyCeiling(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "deploy", "k8s.yaml"))
	if err != nil {
		t.Fatalf("read k8s.yaml: %v", err)
	}
	manifest := string(body)
	if !strings.Contains(manifest, "maxBody: 2097152") {
		t.Error("deploy/k8s.yaml does not declare maxBody: 2097152 in the policy ConfigMap")
	}
	if !strings.Contains(manifest, "AIVAN_MAX_BODY") {
		t.Error("deploy/k8s.yaml does not set AIVAN_MAX_BODY explicitly")
	}
}
