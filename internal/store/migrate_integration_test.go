//go:build integration

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/store"
	"github.com/chris/aivan-authz/test/harness"
)

// TestMigrateFreshDatabase is the B8 item: a fresh database gains authz.* and
// two recorded versions, and a second run is a no-op.
func TestMigrateFreshDatabase(t *testing.T) {
	ctx := context.Background()
	dsn := harness.CreateDatabase(t)
	harness.Exec(t, dsn, `
		create table public.users (
		  id bigint primary key, email text, username text, active boolean default true,
		  password_digest text
		);
		create table public.groups (id bigint primary key, name text);
		create table public.groups_users (group_id bigint, user_id bigint);
	`)
	harness.CreateRole(t, dsn, harness.ServiceRole, "")

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	applied, err := store.Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	want, err := store.Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	if len(applied) != len(want) {
		t.Fatalf("applied = %v, want all %d versions", applied, len(want))
	}

	for _, table := range []string{
		"schema_migrations", "devices", "nonces", "sessions",
		"pending_enrollments", "audit_log",
	} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`select to_regclass('authz.' || $1) is not null`, table).Scan(&exists); err != nil {
			t.Fatalf("check authz.%s: %v", table, err)
		}
		if !exists {
			t.Errorf("authz.%s missing after migrate", table)
		}
	}

	var versions int
	if err := pool.QueryRow(ctx, `select count(*) from authz.schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if versions != len(want) {
		t.Fatalf("recorded %d versions, want %d", versions, len(want))
	}

	again, err := store.Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Migrate applied %v, want nothing", again)
	}
}

// TestMigrateWithoutApplicationSchema records the dependency the schema
// carries: authz.devices, authz.sessions and authz.pending_enrollments all
// reference public.users, and 0002 grants column-level access to the
// application's tables. A gateway therefore cannot be migrated before the
// application's schema exists, and the failure names the migration rather than
// leaving a half-applied schema.
func TestMigrateWithoutApplicationSchema(t *testing.T) {
	ctx := context.Background()
	dsn := harness.CreateDatabase(t)
	harness.CreateRole(t, dsn, harness.ServiceRole, "")

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	applied, err := store.Migrate(ctx, pool)
	if err == nil {
		t.Fatalf("Migrate succeeded without public.users; applied %v", applied)
	}
	if len(applied) != 0 {
		t.Fatalf("applied = %v, want nothing before the failure", applied)
	}
	if !strings.Contains(err.Error(), "0001_init.sql") {
		t.Fatalf("error %q does not name the failing migration", err)
	}

	// Nothing survived the failed transaction, so a later run that has the
	// application schema applies both versions cleanly.
	var exists bool
	if err := pool.QueryRow(ctx, `select to_regclass('authz.devices') is not null`).Scan(&exists); err != nil {
		t.Fatalf("check authz.devices: %v", err)
	}
	if exists {
		t.Fatal("authz.devices exists after a failed migration")
	}
}

// TestMigrateIsSerialised runs two migrations at once; the advisory lock must
// stop them from interleaving and each version must be recorded exactly once.
func TestMigrateIsSerialised(t *testing.T) {
	ctx := context.Background()
	dsn := harness.CreateDatabase(t)
	harness.Exec(t, dsn, `
		create table public.users (id bigint primary key, username text, active boolean, password_digest text);
		create table public.groups (id bigint primary key, name text);
		create table public.groups_users (group_id bigint, user_id bigint);
	`)
	harness.CreateRole(t, dsn, harness.ServiceRole, "")

	pools := make([]*pgxpool.Pool, 2)
	for i := range pools {
		p, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("pool %d: %v", i, err)
		}
		defer p.Close()
		pools[i] = p
	}

	errs := make(chan error, 2)
	for _, p := range pools {
		go func(p *pgxpool.Pool) {
			_, err := store.Migrate(ctx, p)
			errs <- err
		}(p)
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
	}

	var n int
	if err := pools[0].QueryRow(ctx, `select count(*) from authz.schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	want, err := store.Migrations()
	if err != nil {
		t.Fatalf("Migrations: %v", err)
	}
	if n != len(want) {
		t.Fatalf("recorded %d versions, want %d", n, len(want))
	}
}
