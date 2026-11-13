//go:build integration

package main_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/chris/aivan-authz/test/harness"
)

var (
	buildOnce sync.Once
	binPath   string
	buildDir  string
	buildErr  error
)

// TestMain removes the temporary build directory the binary lives in.
func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// binary builds cmd/authz once per test run. The checklist items are about the
// process's exit behaviour, so they are checked against the real binary rather
// than against a package function.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aivz-bin-")
		if err != nil {
			buildErr = err
			return
		}
		buildDir = dir
		out := filepath.Join(dir, "authz")
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, ".")
		cmd.Env = os.Environ()
		if body, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build: %v: %s", err, body)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	return binPath
}

// serveEnv is a complete, valid environment pointing at dsn.
func serveEnv(t *testing.T, dsn, listen string) []string {
	t.Helper()
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin, class: admin }
      - { prefix: /,      class: authenticated }
`
	if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return append(os.Environ(),
		"AIVAN_DB_URL="+dsn,
		"AIVAN_HOSTS=aivan-hud.home.arpa",
		"AIVAN_POLICY="+policy,
		"AIVAN_LISTEN="+listen,
	)
}

// runServe runs `authz serve` to completion and returns its exit code and
// combined output.
func runServe(t *testing.T, env []string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary(t), "serve")
	cmd.Env = env
	out, err := cmd.CombinedOutput()

	if ctx.Err() != nil {
		t.Fatalf("serve did not exit within 30s; output: %s", out)
	}
	var exitErr *exec.ExitError
	if err == nil {
		return 0, string(out)
	}
	if !errors.As(err, &exitErr) {
		t.Fatalf("serve: %v; output: %s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// TestServeRefusesSuperuser is S16 via the binary: exit non-zero, and the
// message tells an operator what to do.
func TestServeRefusesSuperuser(t *testing.T) {
	_, super := harness.Setup(t)

	code, out := runServe(t, serveEnv(t, super, "127.0.0.1:0"))
	if code == 0 {
		t.Fatalf("serve exited 0 under a superuser credential; output: %s", out)
	}
	for _, want := range []string{
		"refusing to start",
		"can create objects in schema public",
		"The service must run as a role with only the grants in 0002_grants.sql.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "postgres://") {
		t.Errorf("refusal leaked the DSN:\n%s", out)
	}
}

// TestServeRefusesPasswordDigest is S20 via the binary.
func TestServeRefusesPasswordDigest(t *testing.T) {
	_, super := harness.Setup(t)

	const role = "serve_digest_reader"
	harness.CreateRole(t, super, role, "")
	harness.Exec(t, super, `
		grant usage on schema authz to `+role+`;
		grant select, insert, update, delete on all tables in schema authz to `+role+`;
		grant usage on sequence authz.audit_log_id_seq to `+role+`;
		grant usage on schema public to `+role+`;
		grant select (id, username, active) on public.users to `+role+`;
		grant select (password_digest) on public.users to `+role+`;
		revoke create on schema public from `+role+`;
	`)

	code, out := runServe(t, serveEnv(t, harness.AsRole(t, super, role), "127.0.0.1:0"))
	if code == 0 {
		t.Fatalf("serve exited 0 with a password_digest-capable credential; output: %s", out)
	}
	if !strings.Contains(out, "password_digest") {
		t.Fatalf("output does not name password_digest:\n%s", out)
	}
}

// TestServeStartsAndDrains is the positive half: the correct role starts, logs
// one line, answers /healthz, and exits 0 on SIGTERM.
func TestServeStartsAndDrains(t *testing.T) {
	service, _ := harness.Setup(t)

	// A port of 0 makes the kernel choose; the startup line carries the real
	// address, which is also what an operator reads.
	env := serveEnv(t, service, "127.0.0.1:0")
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

	logLines := make(chan string, 8)
	go scanLines(stdout, logLines)
	var stderrBuf strings.Builder
	go func() { _, _ = io.Copy(&stderrBuf, stderr) }()

	var addr string
	deadline := time.After(20 * time.Second)
	for addr == "" {
		select {
		case line, ok := <-logLines:
			if !ok {
				t.Fatalf("serve exited before logging its startup line; stderr: %s", stderrBuf.String())
			}
			var rec struct {
				Level string `json:"level"`
				Msg   string `json:"msg"`
				Addr  string `json:"listen"`
				Hosts int    `json:"hosts"`
				Path  string `json:"policy"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("startup line is not JSON: %q (%v)", line, err)
			}
			if rec.Level != "INFO" {
				continue
			}
			if rec.Msg == "listening" {
				addr = rec.Addr
				if rec.Hosts != 1 {
					t.Errorf("startup line hosts = %d, want 1", rec.Hosts)
				}
				if rec.Path == "" {
					t.Errorf("startup line does not name the policy file")
				}
			}
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatalf("no startup line within 20s; stderr: %s", stderrBuf.String())
		}
	}

	// The log prints the listener's Addr; normalise a wildcard or IPv6 form so
	// a client can dial it.
	dial := dialable(addr)

	code := waitForStatus(t, "http://"+dial+"/healthz", http.StatusOK)
	if code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", code)
	}

	resp, err := http.Get("http://" + dial + "/readyz")
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz = %d %q, want 200", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if got := resp.Header.Get("X-Aivan-Request-Id"); len(got) != 32 {
		t.Errorf("readiness response has no request id, got %q", got)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve did not exit 0 on SIGTERM: %v; stderr: %s", err, stderrBuf.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("serve did not exit within 15s of SIGTERM")
	}
}

// TestMigrateSubcommandExitsOne proves `authz migrate` fails with exit 1 and a
// legible error when the application schema is absent.
func TestMigrateSubcommandExitsOne(t *testing.T) {
	dsn := harness.CreateDatabase(t)
	harness.CreateRole(t, dsn, harness.ServiceRole, "")

	cmd := exec.Command(binary(t), "migrate")
	cmd.Env = append(os.Environ(), "AIVAN_DB_URL="+dsn)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("migrate exited 0 without public.users; output: %s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("migrate: %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1; output: %s", exitErr.ExitCode(), out)
	}
	if !strings.Contains(string(out), "0001_init.sql") {
		t.Errorf("output does not name the failing migration:\n%s", out)
	}
}

func scanLines(r io.Reader, out chan<- string) {
	defer close(out)
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		out <- s.Text()
	}
}

// dialable turns a listen address into something a local client can reach.
func dialable(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func waitForStatus(t *testing.T, url string, want int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := 0
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			last = resp.StatusCode
			resp.Body.Close()
			if last == want {
				return last
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last
}
