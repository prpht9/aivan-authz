//go:build integration

package console_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/console"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/test/harness"
)

// clearDevices removes the shared fixture's devices and pending records, so a
// test that mints one of its own is not refused by the partial unique index.
func clearDevices(t *testing.T, f fixture) {
	t.Helper()
	harness.Exec(t, f.super, `
		delete from authz.pending_enrollments;
		delete from authz.sessions;
		delete from authz.devices;`)
}

// harnessAge moves a record's expiry into the past, so the expiry path is a
// state rather than a sleep.
func harnessAge(t *testing.T, f fixture, recordID string) {
	t.Helper()
	harness.Exec(t, f.super, fmt.Sprintf(
		`update authz.pending_enrollments set expires_at = now() - interval '1 second' where id = '%s'`,
		recordID))
}

var hudHosts = []string{"aivan-hud.home.arpa", "second.home.arpa"}

// TestEnrollMintsTheFirstCode is the happy path: a code, a record whose digest
// matches it, and a live TTL.
func TestEnrollMintsTheFirstCode(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)

	res, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "alice",
		Origin:   "aivan-hud.home.arpa",
		Kind:     "browser",
	}, hudHosts, "operator")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if res.UserID != 1 || res.Username != "alice" {
		t.Errorf("user = %d/%q, want 1/alice", res.UserID, res.Username)
	}
	if !strings.Contains(res.Code, "-") {
		t.Errorf("code %q has no display dashes", res.Code)
	}
	normalised := proof.NormalizeEnrollCode(res.Code)
	if !proof.ValidEnrollCode(normalised) {
		t.Fatalf("code %q does not normalise to a valid code", res.Code)
	}
	if got := time.Until(res.Expires); got > console.EnrollTTL || got < console.EnrollTTL-time.Minute {
		t.Errorf("TTL = %s, want about %s", got, console.EnrollTTL)
	}

	// The row holds the digest of the normalised code, not the code.
	var (
		stored []byte
		kind   string
		origin string
	)
	if err := f.pool.QueryRow(context.Background(), `
select code_hash, kind, origin from authz.pending_enrollments where id = $1`,
		res.RecordID).Scan(&stored, &kind, &origin); err != nil {
		t.Fatalf("read record: %v", err)
	}
	want := proof.SHA256Sum([]byte(normalised))
	if !bytes.Equal(stored, want[:]) {
		t.Error("stored digest is not sha256 of the normalised code")
	}
	if kind != "browser" || origin != "aivan-hud.home.arpa" {
		t.Errorf("record = %s/%s", origin, kind)
	}

	// The code is not recoverable from the row.
	if strings.Contains(string(stored), normalised) {
		t.Fatal("the record stores the code itself")
	}
}

// TestEnrollWritesAnAuditRow names the operator and the record.
func TestEnrollWritesAnAuditRow(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	res, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "alice", Origin: "aivan-hud.home.arpa",
	}, hudHosts, "some-operator")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	var (
		decision, reason, actor, subject string
	)
	if err := f.pool.QueryRow(context.Background(), `
select decision, reason, actor, subject_id::text
  from authz.audit_log where route = 'console' order by id desc limit 1`,
	).Scan(&decision, &reason, &actor, &subject); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if decision != "enroll" || reason != "minted" {
		t.Errorf("audit = %s/%s, want enroll/minted", decision, reason)
	}
	if actor != "some-operator" {
		t.Errorf("actor = %q, want some-operator", actor)
	}
	if subject != res.RecordID {
		t.Errorf("subject = %q, want the record %q", subject, res.RecordID)
	}
}

// TestEnrollRefusesAnUnknownUser keeps a typo a console error rather than a
// record attached to nobody.
func TestEnrollRefusesAnUnknownUser(t *testing.T) {
	f := setup(t)
	_, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "nobody", Origin: "aivan-hud.home.arpa",
	}, hudHosts, "operator")
	if err == nil || !strings.Contains(err.Error(), "no active user") {
		t.Fatalf("err = %v, want a refusal naming the user", err)
	}
}

// TestEnrollRefusesAnOriginOutsideHosts: a typo in the host is refused, so a
// record cannot be minted for a host no gate serves.
func TestEnrollRefusesAnOriginOutsideHosts(t *testing.T) {
	f := setup(t)
	_, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "alice", Origin: "aivan-typo.home.arpa",
	}, hudHosts, "operator")
	if err == nil || !strings.Contains(err.Error(), "is not in AIVAN_HOSTS") {
		t.Fatalf("err = %v, want a refusal naming AIVAN_HOSTS", err)
	}
}

// TestEnrollRefusesALiveDevice: one browser device per origin already exists,
// which is the partial unique index's rule surfaced as an operator message.
func TestEnrollRefusesALiveDevice(t *testing.T) {
	f := setup(t)
	_, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "alice", Origin: "aivan-hud.home.arpa", Kind: "browser",
	}, hudHosts, "operator")
	if err == nil {
		t.Fatal("Enroll minted a code for a person who already has a browser device")
	}
	for _, want := range []string{"already has a live browser device", "authz revoke --device"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestEnrollRefusesASecondLiveCode: an unclaimed record is a code in someone's
// hand. A second one would be a second live code for one slot.
func TestEnrollRefusesASecondLiveCode(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	opts := console.EnrollOptions{Username: "alice", Origin: "aivan-hud.home.arpa", Kind: "browser"}

	first, err := console.Enroll(context.Background(), f.pool, opts, hudHosts, "operator")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err = console.Enroll(context.Background(), f.pool, opts, hudHosts, "operator")
	if err == nil {
		t.Fatal("a second live code was minted")
	}
	if !strings.Contains(err.Error(), "unclaimed enrollment already exists") {
		t.Errorf("error %q does not name the existing record", err)
	}
	// The message carries the existing expiry, so the operator knows how long
	// to wait without another command.
	if !strings.Contains(err.Error(), first.Expires.UTC().Format(time.RFC3339)) {
		t.Errorf("error %q does not carry the existing expiry", err)
	}
	if !strings.Contains(err.Error(), first.RecordID) {
		t.Errorf("error %q does not name the record", err)
	}
}

// TestEnrollReplacesAnExpiredRecord: an expired unclaimed record cannot be
// claimed and must not block a fresh mint.
func TestEnrollReplacesAnExpiredRecord(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	opts := console.EnrollOptions{Username: "alice", Origin: "aivan-hud.home.arpa", Kind: "browser"}

	first, err := console.Enroll(context.Background(), f.pool, opts, hudHosts, "operator")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	harnessAge(t, f, first.RecordID)

	second, err := console.Enroll(context.Background(), f.pool, opts, hudHosts, "operator")
	if err != nil {
		t.Fatalf("mint after expiry: %v", err)
	}
	if second.RecordID == first.RecordID {
		t.Fatal("the expired record was reused")
	}

	// The expired row is gone and exactly one live record remains.
	var rows, live int
	if err := f.pool.QueryRow(context.Background(), `
select count(*), count(*) filter (where claimed_at is null and expires_at > now())
  from authz.pending_enrollments where user_id = 1`).Scan(&rows, &live); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 || live != 1 {
		t.Fatalf("rows=%d live=%d, want 1 and 1", rows, live)
	}
}

// TestEnrollRefusesAKindWithNoClaimEndpoint: the claim route accepts browser
// only, so a phone or tablet code would be a credential with nowhere to spend
// it. The console refuses instead of printing one.
func TestEnrollRefusesAKindWithNoClaimEndpoint(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	for _, kind := range []string{"phone", "tablet"} {
		_, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
			Username: "alice", Origin: "aivan-hud.home.arpa", Kind: kind,
		}, hudHosts, "operator")
		if err == nil {
			t.Fatalf("%s was accepted, but the claim endpoint serves browser only", kind)
		}
		if !strings.Contains(err.Error(), "no claim endpoint") {
			t.Errorf("%s: error %q does not explain why", kind, err)
		}
	}
}

// TestWriteEnrollPrintsTheCodeOnce: the printed block carries the code first,
// and there is no second path that prints it.
func TestWriteEnrollPrintsTheCodeOnce(t *testing.T) {
	f := setup(t)
	clearDevices(t, f)
	res, err := console.Enroll(context.Background(), f.pool, console.EnrollOptions{
		Username: "alice", Origin: "aivan-hud.home.arpa",
	}, hudHosts, "operator")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	var out bytes.Buffer
	if err := console.WriteEnroll(&out, res); err != nil {
		t.Fatalf("WriteEnroll: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, res.Code) {
		t.Fatal("output does not print the code")
	}
	if n := strings.Count(text, res.Code); n != 1 {
		t.Fatalf("the code appears %d times, want once", n)
	}
	if !strings.HasPrefix(text, "enrollment code: ") {
		t.Errorf("first line is %q", strings.SplitN(text, "\n", 2)[0])
	}
	if !strings.Contains(text, "/__aivan/enroll") {
		t.Error("output does not say where to enter the code")
	}
}
