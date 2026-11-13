//go:build integration

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

// TestPrivilegeProbeAcceptsServiceRole proves the probe passes under the role
// 0002_grants.sql produces. Without this, a probe that always refuses would
// look like a passing security test.
func TestPrivilegeProbeAcceptsServiceRole(t *testing.T) {
	service, _ := harness.Setup(t)
	ctx := context.Background()

	db, err := store.Open(ctx, service)
	if err != nil {
		t.Fatalf("open as service role: %v", err)
	}
	defer db.Close()

	if err := store.PrivilegeProbe(ctx, db.Pool); err != nil {
		t.Fatalf("probe refused the service role: %v", err)
	}
}

// TestPrivilegeProbeRefusesSuperuser is S16: a credential that can create
// objects in public never starts.
func TestPrivilegeProbeRefusesSuperuser(t *testing.T) {
	_, super := harness.Setup(t)
	ctx := context.Background()

	db, err := store.Open(ctx, super)
	if err != nil {
		t.Fatalf("open as superuser: %v", err)
	}
	defer db.Close()

	err = store.PrivilegeProbe(ctx, db.Pool)
	if err == nil {
		t.Fatal("probe accepted a superuser credential")
	}
	var refusal *store.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("error is %T, want *store.Refusal: %v", err, err)
	}
	for _, want := range []string{
		"refusing to start",
		"can create objects in schema public",
		"only the grants in 0002_grants.sql",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q missing %q", err.Error(), want)
		}
	}
}

// TestPrivilegeProbeRefusesPasswordDigest is S20: holding the column-level
// grant the design deliberately withholds is also a refusal.
func TestPrivilegeProbeRefusesPasswordDigest(t *testing.T) {
	_, super := harness.Setup(t)
	ctx := context.Background()

	const role = "probe_digest_reader"
	harness.CreateRole(t, super, role, "")
	harness.Exec(t, super, `
		grant usage on schema authz to `+role+`;
		grant select, insert, update, delete on all tables in schema authz to `+role+`;
		grant usage on sequence authz.audit_log_id_seq to `+role+`;
		grant usage on schema public to `+role+`;
		grant select (id, username, active) on public.users to `+role+`;
		grant select (id, name) on public.groups to `+role+`;
		grant select on public.groups_users to `+role+`;
		revoke create on schema public from `+role+`;
		grant select (password_digest) on public.users to `+role+`;
	`)

	dsn := harness.AsRole(t, super, role)
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open as %s: %v", role, err)
	}
	defer db.Close()

	err = store.PrivilegeProbe(ctx, db.Pool)
	if err == nil {
		t.Fatal("probe accepted a credential that can read password_digest")
	}
	if !strings.Contains(err.Error(), "password_digest") {
		t.Fatalf("error %q does not name password_digest", err)
	}
}

// TestPrivilegeProbeRefusesWritableUsers covers the insert assertion on its
// own: a role with no CREATE and no password_digest read, but with INSERT on
// public.users, is still over-privileged.
func TestPrivilegeProbeRefusesWritableUsers(t *testing.T) {
	_, super := harness.Setup(t)
	ctx := context.Background()

	const role = "probe_users_writer"
	harness.CreateRole(t, super, role, "")
	harness.Exec(t, super, `
		grant usage on schema authz to `+role+`;
		grant select, insert, update, delete on all tables in schema authz to `+role+`;
		grant usage on schema public to `+role+`;
		grant select (id, username, active) on public.users to `+role+`;
		grant insert (id, username) on public.users to `+role+`;
		revoke create on schema public from `+role+`;
	`)

	db, err := store.Open(ctx, harness.AsRole(t, super, role))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	err = store.PrivilegeProbe(ctx, db.Pool)
	if err == nil {
		t.Fatal("probe accepted a credential that can insert into public.users")
	}
	if !strings.Contains(err.Error(), "insert into public.users") {
		t.Fatalf("error %q does not name the insert privilege", err)
	}
}

// TestPrivilegeProbeReportsWrongEnvironment proves the probe distinguishes
// "denied" from "the schema is not what the design expects". A missing column
// is a refusal with a different message, not a silent pass.
func TestPrivilegeProbeReportsWrongEnvironment(t *testing.T) {
	ctx := context.Background()
	dsn := harness.CreateDatabase(t)
	harness.Exec(t, dsn, `
		create table public.users (id bigint primary key, username text, active boolean);
	`)
	const role = "probe_no_digest_column"
	harness.CreateRole(t, dsn, role, "")
	harness.Exec(t, dsn, `
		grant usage on schema public to `+role+`;
		grant select (id, username, active) on public.users to `+role+`;
		revoke create on schema public from `+role+`;
	`)

	db, err := store.Open(ctx, harness.AsRole(t, dsn, role))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	err = store.PrivilegeProbe(ctx, db.Pool)
	if err == nil {
		t.Fatal("probe accepted a schema without password_digest")
	}
	if !strings.Contains(err.Error(), "SQLSTATE 42501") {
		t.Fatalf("error %q does not explain the expected SQLSTATE", err)
	}
	if !strings.Contains(err.Error(), "does not match the design") {
		t.Fatalf("error %q does not say the environment is wrong", err)
	}
}

// TestPrivilegeProbeLeavesNoTrace asserts the probe's transaction is rolled
// back: the insert it attempts must not create a row.
func TestPrivilegeProbeLeavesNoTrace(t *testing.T) {
	service, super := harness.Setup(t)
	ctx := context.Background()

	serviceDB, err := store.Open(ctx, service)
	if err != nil {
		t.Fatalf("open service: %v", err)
	}
	defer serviceDB.Close()
	if err := store.PrivilegeProbe(ctx, serviceDB.Pool); err != nil {
		t.Fatalf("probe: %v", err)
	}

	var n int
	superDB, err := store.Open(ctx, super)
	if err != nil {
		t.Fatalf("open super: %v", err)
	}
	defer superDB.Close()
	if err := superDB.Pool.QueryRow(ctx,
		`select count(*) from public.users where id = -1 or username = 'privilege-probe'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("probe left %d rows behind", n)
	}
}
