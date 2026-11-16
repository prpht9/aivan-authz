//go:build integration

package console_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// The break-glass purge runs as the operator credential, which is what the
// admin binary uses. setup's pool is already that credential, so these tests
// use f.op directly.
//
// The scheduled purge is a different credential: hud's chart runs the CronJob
// as aivan_core, and TestPurgeRunsAsTheScheduledCredential is what proves that
// role holds exactly what the two statements need.

// insertNonce writes a nonce row directly, with an expiry relative to the
// database's clock, and returns its hash. The test never presents these nonces:
// only the row matters to the purge.
func insertNonce(t *testing.T, super string, device [16]byte, expiresIn time.Duration) []byte {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i) ^ byte(expiresIn.Nanoseconds())
	}
	hash := proof.SHA256Sum(append(raw[:], []byte(fmt.Sprint(expiresIn.Nanoseconds(), device))...))
	harness.Exec(t, super, fmt.Sprintf(
		`insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
		 values (decode('%x','hex'), '%s', now() - interval '2 hours', now() + interval '%d seconds')`,
		hash[:], proof.FormatDeviceID(device), int64(expiresIn.Seconds())))
	return hash[:]
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func rowExists(t *testing.T, pool *pgxpool.Pool, table, column string, hash []byte) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from `+table+` where `+column+` = $1`, hash).Scan(&n); err != nil {
		t.Fatalf("query %s: %v", table, err)
	}
	return n == 1
}

// TestPurgeRemovesExpiredAndKeepsLive is G1's assertion, run through the command
// that owns the purge now: one pass removes an expired nonce and an expired
// session, and leaves a live row of each.
func TestPurgeRemovesExpiredAndKeepsLive(t *testing.T) {
	f := setup(t)

	expiredNonce := insertNonce(t, f.super, f.device, -2*time.Hour)
	liveNonce := insertNonce(t, f.super, f.device, time.Hour)

	// Age the sibling's session past the idle expiry and the grace, so exactly
	// one session is removable and the fixture's own session survives.
	harness.Exec(t, f.super, fmt.Sprintf(
		`update authz.sessions
		    set idle_expires_at = now() - interval '2 hours',
		        absolute_expires_at = now() + interval '1 hour'
		  where device_id = '%s'`, proof.FormatDeviceID(f.sibling)))

	counts, err := console.Purge(context.Background(), f.op)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if counts.Nonces != 1 {
		t.Errorf("purged nonces = %d, want 1", counts.Nonces)
	}
	if counts.Sessions != 1 {
		t.Errorf("purged sessions = %d, want 1", counts.Sessions)
	}

	if rowExists(t, f.op, "authz.nonces", "nonce_hash", expiredNonce) {
		t.Error("the expired nonce survived the purge")
	}
	if !rowExists(t, f.op, "authz.nonces", "nonce_hash", liveNonce) {
		t.Error("the live nonce was purged")
	}
	if n := countRows(t, f.op, "authz.sessions"); n != 1 {
		t.Errorf("sessions after the purge = %d, want the live one", n)
	}
}

// TestPurgeRemovesAbsolutelyExpiredSession: the absolute cap has no grace by
// design, so a session past it is removed even when its idle expiry was
// recently slid forward.
func TestPurgeRemovesAbsolutelyExpiredSession(t *testing.T) {
	f := setup(t)

	harness.Exec(t, f.super, fmt.Sprintf(
		`update authz.sessions
		    set idle_expires_at = now() + interval '10 minutes',
		        absolute_expires_at = now() - interval '1 minute'
		  where device_id = '%s'`, proof.FormatDeviceID(f.sibling)))

	if _, err := console.Purge(context.Background(), f.op); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n := countRows(t, f.op, "authz.sessions"); n != 1 {
		t.Errorf("sessions after the purge = %d, want only the live one", n)
	}
}

// TestPurgeIsAllOrNothing is G1's transactional claim: when the session
// statement fails, the nonce statement's effect is rolled back. The failure is
// caused by renaming the table the second statement targets, then restored.
func TestPurgeIsAllOrNothing(t *testing.T) {
	f := setup(t)

	expiredNonce := insertNonce(t, f.super, f.device, -2*time.Hour)

	harness.Exec(t, f.super, `alter table authz.sessions rename to sessions_purge_probe`)
	renamed := true
	restore := func() {
		if renamed {
			harness.Exec(t, f.super, `alter table authz.sessions_purge_probe rename to sessions`)
			renamed = false
		}
	}
	t.Cleanup(restore)

	if _, err := console.Purge(context.Background(), f.op); err == nil {
		t.Fatal("Purge succeeded with the session table missing")
	}
	if !rowExists(t, f.op, "authz.nonces", "nonce_hash", expiredNonce) {
		t.Fatal("the nonce was deleted although the transaction failed")
	}

	restore()
	counts, err := console.Purge(context.Background(), f.op)
	if err != nil {
		t.Fatalf("Purge after restore: %v", err)
	}
	if counts.Nonces != 1 {
		t.Errorf("purged nonces after restore = %d, want 1", counts.Nonces)
	}
	if rowExists(t, f.op, "authz.nonces", "nonce_hash", expiredNonce) {
		t.Error("the expired nonce survived a successful purge")
	}
}

// TestPurgeGrace pins the grace the statements carry. A row removed inside the
// grace would race a request that had already passed.
func TestPurgeGrace(t *testing.T) {
	if console.PurgeGrace != time.Hour {
		t.Fatalf("PurgeGrace = %s, want 1h", console.PurgeGrace)
	}
}

// TestPurgeRunsOutsideTheGate is the other half of the split. The gate's
// credential still holds DML on the scratch tables — a session is ended by a
// delete, and a nonce is consumed by one — but the statements are not in the
// gate's binary, and the scheduled pass runs as a credential that is not in the
// pod at all.
//
// Two assertions: the operator role the break-glass command uses can run both
// statements, and the gate's credential holds no authority the split keeps out
// of the pod.
func TestPurgeRunsOutsideTheGate(t *testing.T) {
	f := setup(t)

	if _, err := f.op.Exec(context.Background(), console.PurgeNonceSQL); err != nil {
		t.Fatalf("the operator credential cannot purge nonces: %v", err)
	}
	if _, err := f.op.Exec(context.Background(), console.PurgeSessionsSQL); err != nil {
		t.Fatalf("the operator credential cannot purge sessions: %v", err)
	}

	// The gate's credential holds the delete on its scratch tables by design;
	// what it does not hold is EXECUTE on revoke_device, which is the authority
	// this split keeps out of the pod.
	service := harness.Pool(t, f.service)
	var canRevoke bool
	if err := service.QueryRow(context.Background(),
		`select has_function_privilege(current_user,
		        'authz.revoke_device(uuid,text)', 'EXECUTE')`).Scan(&canRevoke); err != nil {
		t.Fatalf("measure revoke_device: %v", err)
	}
	if canRevoke {
		t.Error("the gate's credential can execute authz.revoke_device")
	}
}

// TestPurgeRunsAsTheScheduledCredential pins what the CronJob's role may do.
//
// The scheduled pass is hud's chart, running as aivan_core with hud's own
// DATABASE_URL — not the schema owner, and not the gate. The grant is in
// aivan-hud/db/migration/202611150100_authz_purge_grants.rb, and this test is
// what notices if that migration and these statements drift apart.
//
// Two things are asserted. The role can run both statements as written: DELETE
// alone is not enough, because PostgreSQL requires SELECT on every column a
// WHERE expression reads, so the grant carries a column-level SELECT on the
// predicate columns. And it holds nothing wider: no SELECT on the rows
// themselves, so a compromised hud pod cannot enumerate live sessions or
// unspent nonces.
func TestPurgeRunsAsTheScheduledCredential(t *testing.T) {
	f := setup(t)

	// The application credential, which is what hud's chart mounts.
	app := harness.Pool(t, f.core)

	for name, sql := range map[string]string{
		"nonces":   console.PurgeNonceSQL,
		"sessions": console.PurgeSessionsSQL,
	} {
		if _, err := app.Exec(context.Background(), sql); err != nil {
			t.Errorf("the scheduled credential cannot purge %s: %v", name, err)
		}
	}

	// The predicate columns must be readable, or the statements above could not
	// have run. The identity columns must not be: a purge job has no use for
	// them, and an attacker holding this role would.
	for _, c := range []struct {
		table  string
		column string
		want   bool
	}{
		{"authz.nonces", "expires_at", true},
		{"authz.sessions", "idle_expires_at", true},
		{"authz.sessions", "absolute_expires_at", true},
		{"authz.nonces", "nonce_hash", false},
		{"authz.sessions", "token_hash", false},
	} {
		var has bool
		if err := app.QueryRow(context.Background(),
			`select has_column_privilege(current_user, $1, $2, 'SELECT')`,
			c.table, c.column).Scan(&has); err != nil {
			t.Fatalf("measure %s.%s: %v", c.table, c.column, err)
		}
		if has != c.want {
			t.Errorf("%s.%s SELECT = %v, want %v", c.table, c.column, has, c.want)
		}
	}
}
