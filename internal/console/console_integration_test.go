//go:build integration

package console_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

// setup builds the harness database and seeds an alice with a device and one
// live session, plus a second device for the same person.
type fixture struct {
	pool    *pgxpool.Pool
	service string
	super   string
	device  [16]byte
	sibling [16]byte
	// token is the live session's cookie value.
	token string
}

func setup(t *testing.T) fixture {
	t.Helper()
	service, super := harness.Setup(t)

	db, err := store.Open(context.Background(), service)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	harness.Exec(t, super, `
		delete from authz.devices;
		delete from public.groups_users;
		delete from public.groups;
		delete from public.users;
		insert into public.users (id, email, username, active) values
			(1, 'alice@example.invalid', 'alice', true);
		insert into public.groups (id, name) values (10, 'admin');
		insert into public.groups_users (group_id, user_id) values (10, 1);
	`)

	f := fixture{pool: db.Pool, service: service, super: super}
	f.device = insertDevice(t, super, 1, "aivan-hud.home.arpa", "browser")
	f.sibling = insertDevice(t, super, 1, "aivan-hud.home.arpa", "phone")
	f.token = insertSession(t, super, f.device, "15 minutes", "8 hours")
	// A session for the sibling, to prove revoke is per device.
	insertSession(t, super, f.sibling, "15 minutes", "8 hours")
	return f
}

func insertDevice(t *testing.T, super string, userID int64, origin, kind string) [16]byte {
	t.Helper()
	var id [16]byte
	copy(id[:], fmt.Sprintf("%-16s", kind))
	harness.Exec(t, super, fmt.Sprintf(`
		insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
		values ('%s', %d, '%s', 'test', '%s', decode('00', 'hex'), 'ed25519')`,
		proof.FormatDeviceID(id), userID, origin, kind))
	return id
}

func insertSession(t *testing.T, super string, device [16]byte, idle, absolute string) string {
	t.Helper()
	token := strings.Repeat("t", 43)
	// A unique token per row: derive it from the device so two devices do not
	// collide on the primary key.
	token = fmt.Sprintf("%s%s", proof.FormatDeviceID(device)[:8], token[:35])
	hash := proof.SHA256Sum([]byte(token))
	harness.Exec(t, super, fmt.Sprintf(`
		insert into authz.sessions (token_hash, device_id, idle_expires_at, absolute_expires_at)
		values (decode('%x', 'hex'), '%s', now() + interval '%s', now() + interval '%s')`,
		hash[:], proof.FormatDeviceID(device), idle, absolute))
	return token
}

func countSessions(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `select count(*) from authz.sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

func revokedAt(t *testing.T, pool *pgxpool.Pool, device [16]byte) *time.Time {
	t.Helper()
	var at *time.Time
	if err := pool.QueryRow(context.Background(),
		`select revoked_at from authz.devices where id = $1`, proof.FormatDeviceID(device)).Scan(&at); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	return at
}

// TestRevokeDeletesSessionsAndWritesAudit is the happy path: one transaction
// revokes the device, kills only its sessions, and records the event.
func TestRevokeDeletesSessionsAndWritesAudit(t *testing.T) {
	f := setup(t)
	if n := countSessions(t, f.pool); n != 2 {
		t.Fatalf("sessions before revoke = %d, want 2", n)
	}

	res, err := console.Revoke(context.Background(), f.pool, proof.FormatDeviceID(f.device), console.Hook{})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.Sessions != 1 {
		t.Errorf("sessions deleted = %d, want 1", res.Sessions)
	}
	if res.AlreadyRevoked {
		t.Error("a first revoke reported AlreadyRevoked")
	}
	if res.UserID != 1 {
		t.Errorf("user id = %d, want 1", res.UserID)
	}

	if revokedAt(t, f.pool, f.device) == nil {
		t.Fatal("revoked_at was not set")
	}
	if n := countSessions(t, f.pool); n != 1 {
		t.Fatalf("sessions after revoke = %d, want the sibling's 1", n)
	}
	if revokedAt(t, f.pool, f.sibling) != nil {
		t.Fatal("revoke touched the sibling device")
	}

	var decision, reason string
	if err := f.pool.QueryRow(context.Background(), `
select decision, reason from authz.audit_log
 where device_id = $1 order by id desc limit 1`, proof.FormatDeviceID(f.device)).Scan(&decision, &reason); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if decision != "revoke" || reason != "device_revoked" {
		t.Fatalf("audit row = %s/%s, want revoke/device_revoked", decision, reason)
	}
}

// TestRevokeIsIdempotent: a second revoke reports that it was already revoked
// and still succeeds, so a retry after a partial failure is safe.
func TestRevokeIsIdempotent(t *testing.T) {
	f := setup(t)
	id := proof.FormatDeviceID(f.device)

	if _, err := console.Revoke(context.Background(), f.pool, id, console.Hook{}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	res, err := console.Revoke(context.Background(), f.pool, id, console.Hook{})
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if !res.AlreadyRevoked {
		t.Error("second revoke did not report AlreadyRevoked")
	}
	if res.Sessions != 0 {
		t.Errorf("second revoke deleted %d sessions, want 0", res.Sessions)
	}
}

// TestRevokeUnknownDeviceIsAnError: an id that matches nothing tells the
// operator so instead of reporting a success that changed nothing.
func TestRevokeUnknownDeviceIsAnError(t *testing.T) {
	f := setup(t)
	_, err := console.Revoke(context.Background(), f.pool,
		"3f2504e0-4f89-41d3-9a0c-0305e82c3301", console.Hook{})
	if err == nil {
		t.Fatal("revoke of an unknown device succeeded")
	}
	if !strings.Contains(err.Error(), "no device") {
		t.Fatalf("error = %v, want it to name the missing device", err)
	}

	for _, bad := range []string{"", "not-a-uuid", strings.Repeat("0", 36)} {
		if _, err := console.Revoke(context.Background(), f.pool, bad, console.Hook{}); err == nil {
			t.Errorf("revoke accepted %q", bad)
		}
	}
}

// TestRevokeIsTransactionalAcrossACrash is D7's mid-flight kill. The helper
// test below re-executes this binary, revokes with a hook that SIGKILLs the
// process after revoked_at is set and before the sessions are deleted, and the
// parent then asserts the database has neither a revoked device nor a deleted
// session.
func TestRevokeIsTransactionalAcrossACrash(t *testing.T) {
	f := setup(t)
	id := proof.FormatDeviceID(f.device)

	cmd := exec.Command(os.Args[0], "-test.run=^TestRevokeCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		crashEnv+"=1",
		"AIVAN_CRASH_DSN="+f.service,
		"AIVAN_CRASH_DEVICE="+id,
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("helper did not die: %v; output: %s", err, out)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("helper exit = %v, want SIGKILL; output: %s", exitErr, out)
	}
	if !strings.Contains(string(out), "helper: revoked_at set") {
		t.Fatalf("helper did not reach the crash point; output: %s", out)
	}

	// Neither half survived: PostgreSQL rolled the whole transaction back.
	if at := revokedAt(t, f.pool, f.device); at != nil {
		t.Fatalf("revoked_at survived the crash: %s", at)
	}
	if n := countSessions(t, f.pool); n != 2 {
		t.Fatalf("sessions after the crash = %d, want both still live", n)
	}

	// A retry after the crash completes the revoke, so an operator who sees a
	// killed process can simply run the command again.
	res, err := console.Revoke(context.Background(), f.pool, id, console.Hook{})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if res.Sessions != 1 {
		t.Fatalf("retry deleted %d sessions, want 1", res.Sessions)
	}
	if at := revokedAt(t, f.pool, f.device); at == nil {
		t.Fatal("retry did not set revoked_at")
	}
}

const crashEnv = "AIVAN_CRASH_HELPER"

// TestRevokeCrashHelper is the child half of the crash test. It is skipped
// unless the parent started it, so a normal run never kills a process.
func TestRevokeCrashHelper(t *testing.T) {
	if os.Getenv(crashEnv) == "" {
		t.Skip("helper for TestRevokeIsTransactionalAcrossACrash")
	}
	dsn := os.Getenv("AIVAN_CRASH_DSN")
	id := os.Getenv("AIVAN_CRASH_DEVICE")

	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	_, err = console.Revoke(context.Background(), db.Pool, id, console.Hook{
		AfterUpdate: func(context.Context, pgx.Tx) error {
			// The device row is updated and no session is deleted yet. Killing
			// here is what a power loss between the two statements looks like
			// to PostgreSQL: the connection drops and the transaction rolls
			// back.
			fmt.Println("helper: revoked_at set")
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {} // unreachable; SIGKILL is not catchable
		},
	})
	t.Fatalf("revoke returned instead of dying: %v", err)
}

// TestListDevices prints one person's devices and nothing of anyone else's.
func TestListDevices(t *testing.T) {
	f := setup(t)

	devices, err := console.ListDevices(context.Background(), f.pool, "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(devices))
	}

	var out bytes.Buffer
	if err := console.WriteDevices(&out, devices); err != nil {
		t.Fatalf("write: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "ID") || !strings.Contains(text, "LAST_SEEN") {
		t.Fatalf("table has no header: %q", text)
	}
	for _, want := range []string{proof.FormatDeviceID(f.device), "browser",
		proof.FormatDeviceID(f.sibling), "phone", "aivan-hud.home.arpa"} {
		if !strings.Contains(text, want) {
			t.Errorf("table missing %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "\n") != 3 {
		t.Errorf("table has %d lines, want a header and two rows:\n%s",
			strings.Count(text, "\n"), text)
	}

	// A person with no devices is an empty table, not an error.
	empty, err := console.ListDevices(context.Background(), f.pool, "nobody")
	if err != nil {
		t.Fatalf("list an unknown user: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("unknown user has %d devices", len(empty))
	}
}
