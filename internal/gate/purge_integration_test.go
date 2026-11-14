//go:build integration

package gate_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
)

// insertNonce writes a nonce row directly, with an expiry relative to the
// database's clock, and returns its hash.
func (e *env) insertNonce(d device, expiresIn time.Duration) []byte {
	e.t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i) ^ byte(len(e.logBuf.String()))
	}
	// Distinct hashes are what the primary key needs; the test never presents
	// these nonces, so only the row matters.
	hash := proof.SHA256Sum(append(raw[:], []byte(fmt.Sprint(expiresIn.Nanoseconds(), d.ID))...))
	harnessExec(e.t, e.super, fmt.Sprintf(
		`insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
		 values (decode('%x','hex'), '%s', now() - interval '2 hours', now() + interval '%d seconds')`,
		hash[:], formatID(d.ID), int64(expiresIn.Seconds())))
	return hash[:]
}

// countRows reads one count from an authz table.
func (e *env) countRows(table string) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(),
		`select count(*) from `+table).Scan(&n); err != nil {
		e.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// rowExists reports whether a row with hash exists in table.
func (e *env) rowExists(table string, hash []byte) bool {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(),
		`select count(*) from `+table+` where `+map[string]string{
			"authz.nonces":   "nonce_hash",
			"authz.sessions": "token_hash",
		}[table]+` = $1`, hash).Scan(&n); err != nil {
		e.t.Fatalf("query %s: %v", table, err)
	}
	return n == 1
}

// TestPurgeRemovesExpiredAndKeepsLive is G1's assertion: one pass removes an
// expired nonce and an expired session, and leaves a live row of each.
func TestPurgeRemovesExpiredAndKeepsLive(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	// Expired long enough ago to be past the grace, and live for an hour.
	expiredNonce := e.insertNonce(d, -2*time.Hour)
	liveNonce := e.insertNonce(d, time.Hour)

	s := e.mint(d)

	// Age the minted session past both the idle expiry and the purge grace.
	aged := proof.SHA256Sum([]byte(s.Cookie))
	harnessExec(t, e.super, fmt.Sprintf(
		`update authz.sessions
		    set idle_expires_at = now() - interval '2 hours',
		        absolute_expires_at = now() + interval '1 hour'
		  where token_hash = decode('%x','hex')`, aged[:]))

	live := e.mint(d)
	liveHash := proof.SHA256Sum([]byte(live.Cookie))

	before := e.countRows("authz.nonces")
	if before < 2 {
		t.Fatalf("nonce rows = %d, want at least 2", before)
	}

	counts, err := e.gate.Purge(context.Background())
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if counts.Nonces != 1 {
		t.Errorf("purged nonces = %d, want 1", counts.Nonces)
	}
	if counts.Sessions != 1 {
		t.Errorf("purged sessions = %d, want 1", counts.Sessions)
	}

	if e.rowExists("authz.nonces", expiredNonce) {
		t.Error("the expired nonce survived the purge")
	}
	if !e.rowExists("authz.nonces", liveNonce) {
		t.Error("the live nonce was purged")
	}
	if e.rowExists("authz.sessions", aged[:]) {
		t.Error("the aged session survived the purge")
	}
	if !e.rowExists("authz.sessions", liveHash[:]) {
		t.Error("the live session was purged")
	}

	// The aged session's cookie is refused because it is expired, and the
	// live one still authenticates. That is the property the purge preserves.
	if r := e.verifyWith(s.Cookie, http.MethodGet, testTarget); r.Status != http.StatusUnauthorized {
		t.Errorf("aged session status = %d, want 401", r.Status)
	}
	if r := e.verifyWith(live.Cookie, http.MethodGet, testTarget); r.Status != http.StatusOK {
		t.Errorf("live session status = %d, want 200", r.Status)
	}
}

// TestPurgeLeavesAnAbsolutelyExpiredSessionRoutedToTheGrace: the absolute cap
// has no grace by design, so a session past it is removed even when its idle
// expiry was recently slid forward.
func TestPurgeRemovesAbsolutelyExpiredSession(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	s := e.mint(d)
	harnessExec(t, e.super, fmt.Sprintf(
		`update authz.sessions
		    set idle_expires_at = now() + interval '10 minutes',
		        absolute_expires_at = now() - interval '1 minute'
		  where device_id = '%s'`, formatID(d.ID)))

	if _, err := e.gate.Purge(context.Background()); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	hash := proof.SHA256Sum([]byte(s.Cookie))
	if e.rowExists("authz.sessions", hash[:]) {
		t.Error("a session past its absolute cap survived the purge")
	}
}

// TestPurgeIsAllOrNothing is G1's transactional claim: when the session
// statement fails, the nonce statement's effect is rolled back. The failure is
// caused by renaming the table the second statement targets, then restored.
func TestPurgeIsAllOrNothing(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	expiredNonce := e.insertNonce(d, -2*time.Hour)

	harnessExec(t, e.super, `alter table authz.sessions rename to sessions_purge_probe`)
	renamed := true
	restore := func() {
		if renamed {
			harnessExec(t, e.super, `alter table authz.sessions_purge_probe rename to sessions`)
			renamed = false
		}
	}
	t.Cleanup(restore)

	if _, err := e.gate.Purge(context.Background()); err == nil {
		t.Fatal("Purge succeeded with the session table missing")
	}

	// The nonce delete ran first and must not have survived the rollback. The
	// gate's own pool would notice the renamed table, so the read is a fresh
	// connection.
	if !e.rowExists("authz.nonces", expiredNonce) {
		t.Fatal("the nonce was deleted although the transaction failed")
	}

	// After the rename is undone, a pass removes it.
	restore()
	counts, err := e.gate.Purge(context.Background())
	if err != nil {
		t.Fatalf("Purge after restore: %v", err)
	}
	if counts.Nonces != 1 {
		t.Errorf("purged nonces after restore = %d, want 1", counts.Nonces)
	}
	if e.rowExists("authz.nonces", expiredNonce) {
		t.Error("the expired nonce survived a successful purge")
	}
}

// purgeIntervalIsAMinute pins the schedule the phase file names.
func TestPurgeIntervalIsAMinute(t *testing.T) {
	if gate.PurgeInterval != time.Minute {
		t.Fatalf("PurgeInterval = %s, want 1m", gate.PurgeInterval)
	}
	if gate.PurgeGrace != time.Hour {
		t.Fatalf("PurgeGrace = %s, want 1h", gate.PurgeGrace)
	}
}
