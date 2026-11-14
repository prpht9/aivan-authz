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

// fixture is a scratch database seeded with an alice, a device she holds and a
// second device of another kind, each with a live session.
//
// pool connects as the operator credential, because every command in this
// package runs as one: aivan_core holds the revoke function and the read of
// devices, and the gate's own credential holds neither (doc/schema-ownership.md
// §4).
type fixture struct {
	// pool is the application credential: revoke and list-devices are hud's
	// actions, and this is the role hud holds.
	pool *pgxpool.Pool
	// op is the operator credential: it owns schema authz, so it reads the
	// scratch tables and runs the purge.
	op      *pgxpool.Pool
	service string
	core    string
	opDSN   string
	super   string
	device  [16]byte
	sibling [16]byte
	// token is the live session's cookie value.
	token string
}

func setup(t *testing.T) fixture {
	t.Helper()
	service, super := harness.Setup(t)

	core := harness.AsRole(t, super, harness.CoreRole)
	db, err := store.Open(context.Background(), core)
	if err != nil {
		t.Fatalf("open as %s: %v", harness.CoreRole, err)
	}
	t.Cleanup(db.Close)

	opDSN := harness.Operator(t, super)
	op, err := store.Open(context.Background(), opDSN)
	if err != nil {
		t.Fatalf("open as %s: %v", harness.MigrationRole, err)
	}
	t.Cleanup(op.Close)

	harness.SeedUsers(t, super,
		[]harness.User{{ID: 1, Username: "alice", Active: true}},
		map[int64]string{10: "admin"},
		map[int64][]int64{10: {1}})

	f := fixture{pool: db.Pool, op: op.Pool, service: service, core: core, opDSN: opDSN, super: super}
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
	if n := countSessions(t, f.op); n != 2 {
		t.Fatalf("sessions before revoke = %d, want 2", n)
	}

	res, err := console.Revoke(context.Background(), f.pool, proof.FormatDeviceID(f.device), "operator")
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

	if revokedAt(t, f.op, f.device) == nil {
		t.Fatal("revoked_at was not set")
	}
	if n := countSessions(t, f.op); n != 1 {
		t.Fatalf("sessions after revoke = %d, want the sibling's 1", n)
	}
	if revokedAt(t, f.op, f.sibling) != nil {
		t.Fatal("revoke touched the sibling device")
	}

	// The evidence is read as the operator: no application or gate credential
	// can read authz.audit_log, which is what keeps a compromised process from
	// scrubbing the record of itself.
	var decision, reason string
	if err := f.op.QueryRow(context.Background(), `
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

	if _, err := console.Revoke(context.Background(), f.pool, id, "operator"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	res, err := console.Revoke(context.Background(), f.pool, id, "operator")
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
		"3f2504e0-4f89-41d3-9a0c-0305e82c3301", "operator")
	if err == nil {
		t.Fatal("revoke of an unknown device succeeded")
	}
	if !strings.Contains(err.Error(), "no device") {
		t.Fatalf("error = %v, want it to name the missing device", err)
	}

	for _, bad := range []string{"", "not-a-uuid", strings.Repeat("0", 36)} {
		if _, err := console.Revoke(context.Background(), f.pool, bad, "operator"); err == nil {
			t.Errorf("revoke accepted %q", bad)
		}
	}
}

// TestRevokeIsTransactionalAcrossACrash is D7's mid-flight kill, expressed
// against the function that performs the revoke now.
//
// authz.revoke_device() sets revoked_at, deletes the device's sessions and
// writes the audit row as one transaction. The helper below runs it inside a
// client transaction of its own and SIGKILLs the process before the commit, so
// the database sees exactly what a power loss between the statements looks like:
// a connection that drops with an open transaction.
func TestRevokeIsTransactionalAcrossACrash(t *testing.T) {
	f := setup(t)
	id := proof.FormatDeviceID(f.device)

	cmd := exec.Command(os.Args[0], "-test.run=^TestRevokeCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		crashEnv+"=1",
		"AIVAN_CRASH_DSN="+f.core,
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
	if !strings.Contains(string(out), "helper: revoke called, not committed") {
		t.Fatalf("helper did not reach the crash point; output: %s", out)
	}

	// Neither half survived: PostgreSQL rolled the whole transaction back.
	if at := revokedAt(t, f.op, f.device); at != nil {
		t.Fatalf("revoked_at survived the crash: %s", at)
	}
	if n := countSessions(t, f.op); n != 2 {
		t.Fatalf("sessions after the crash = %d, want both still live", n)
	}

	// A retry after the crash completes the revoke, so an operator who sees a
	// killed process can simply run the command again.
	res, err := console.Revoke(context.Background(), f.pool, id, "operator")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if res.Sessions != 1 {
		t.Fatalf("retry deleted %d sessions, want 1", res.Sessions)
	}
	if at := revokedAt(t, f.op, f.device); at == nil {
		t.Fatal("retry did not set revoked_at")
	}
}

const crashEnv = "AIVAN_CRASH_HELPER"

// TestRevokeCrashHelper is the child half of the crash test. It is skipped
// unless the parent started it, so a normal run never kills a process.
//
// It connects with the operator credential, because the gate's credential is
// refused EXECUTE on authz.revoke_device and that refusal is a different test.
// It uses a single connection rather than the pool so the process can be killed
// with its transaction still open.
func TestRevokeCrashHelper(t *testing.T) {
	if os.Getenv(crashEnv) == "" {
		t.Skip("helper for TestRevokeIsTransactionalAcrossACrash")
	}
	dsn := os.Getenv("AIVAN_CRASH_DSN")
	id := os.Getenv("AIVAN_CRASH_DEVICE")

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// The function has run inside the transaction: the device row is updated
	// and its sessions are deleted, and none of it is visible outside. Killing
	// here is what a power loss between the statements looks like.
	if _, err := tx.Exec(ctx, `select * from authz.revoke_device($1, 'crash-helper')`, id); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("revoke_device: %v", err)
	}
	fmt.Println("helper: revoke called, not committed")
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {} // unreachable; SIGKILL is not catchable
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
