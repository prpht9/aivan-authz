//go:build integration

// Package harness builds a scratch database for integration tests: the hud
// fixture, the aivan_authz service role, and the gate's migrations. It mirrors
// what the install step does on a real cluster, because the migration that
// grants column-level access depends on the application's tables existing.
package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/store"
)

// ServiceRole is the role 0002_grants.sql names. Another name would leave the
// grants pointing at a role that does not exist.
const ServiceRole = "aivan_authz"

// DefaultSuperuser is where the integration tests expect a cluster they may
// create roles and databases on.
const DefaultSuperuser = "postgres://postgres@localhost/postgres"

// Env skips the test when no cluster is reachable.
func Env(t testing.TB) {
	t.Helper()
	if super := superuserDSN(); !reachable(super) {
		t.Skipf("no superuser database at %s; set AIVAN_TEST_SUPERUSER_URL", super)
	}
}

// Setup creates a scratch database with the fixture, the service role and the
// migrations applied, and returns DSNs for it. Cleanup is registered on t.
func Setup(t testing.TB) (service, super string) {
	t.Helper()
	Env(t)
	ctx := context.Background()

	super = createDatabase(t, superuserDSN())
	service = withDatabase(t, serviceDSN(), databaseName(super))

	admin, err := pgx.Connect(ctx, superuserDSN())
	if err != nil {
		t.Fatalf("connect superuser: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	ensureRole(t, ctx, admin)

	// The hud fixture stands in for the application's schema. It is applied as
	// the owner, which is how application migrations run in production.
	applyFile(t, ctx, super, fixturePath(t, "hud_min.sql"))

	// Migrations run as the owner, as the install step does.
	pool, err := pgxpool.New(ctx, super)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if _, err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return service, super
}

// CreateDatabase makes an empty scratch database and returns a superuser DSN
// for it. Cleanup is registered on t.
func CreateDatabase(t testing.TB) string {
	t.Helper()
	Env(t)
	return createDatabase(t, superuserDSN())
}

// AsRole rewrites a DSN to connect as another role, keeping host and database.
func AsRole(t testing.TB, base, role string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.User = url.User(role)
	return u.String()
}

// CreateRole creates a login role with no privileges beyond connecting. A role
// that already exists is left in place, because PostgreSQL roles are
// cluster-wide and tests that need a specific privilege set create their own
// name. grants is optional SQL for what the role should additionally hold.
func CreateRole(t testing.TB, superDSN, role, grants string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, superDSN)
	defer func() { _ = conn.Close(ctx) }()

	var exists bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, role).Scan(&exists); err != nil {
		t.Fatalf("check role %s: %v", role, err)
	}
	if !exists {
		if _, err := conn.Exec(ctx, `create role `+ident(role)+` login nosuperuser nocreatedb nocreaterole`); err != nil {
			t.Fatalf("create role %s: %v", role, err)
		}
	}
	if grants != "" {
		if _, err := conn.Exec(ctx, grants); err != nil {
			t.Fatalf("grants for %s: %v", role, err)
		}
	}
}

// Exec runs statements as a superuser against dsn, for test setup.
func Exec(t testing.TB, dsn, sql string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, dsn)
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func superuserDSN() string {
	if v := os.Getenv("AIVAN_TEST_SUPERUSER_URL"); v != "" {
		return v
	}
	return DefaultSuperuser
}

// serviceDSN defaults to the service role on the same cluster as the
// superuser, because roles are cluster-wide and a scratch cluster is where the
// harness can create them.
func serviceDSN() string {
	if v := os.Getenv("AIVAN_TEST_DB_URL"); v != "" {
		return v
	}
	u, err := url.Parse(superuserDSN())
	if err != nil {
		return "postgres://" + ServiceRole + "@localhost/aivan_authz_test"
	}
	u.User = url.User(ServiceRole)
	u.Path = "/aivan_authz_test"
	return u.String()
}

func reachable(dsn string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return false
	}
	_ = conn.Close(ctx)
	return true
}

func createDatabase(t testing.TB, superDSN string) string {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, superDSN)
	defer func() { _ = conn.Close(ctx) }()

	name := "aivz_b_" + suffix(t)
	if _, err := conn.Exec(ctx, `create database `+ident(name)); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := pgx.Connect(cleanupCtx, superDSN)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(cleanupCtx) }()
		_, _ = c.Exec(cleanupCtx, `drop database if exists `+ident(name)+` with (force)`)
	})
	return withDatabase(t, superDSN, name)
}

// ensureRole creates the service role if it is missing. The grant migration
// names it, and the service DSN cannot connect without it.
func ensureRole(t testing.TB, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, ServiceRole).Scan(&exists); err != nil {
		t.Fatalf("check role: %v", err)
	}
	if exists {
		return
	}
	stmt := `create role ` + ident(ServiceRole) + ` login nosuperuser nocreatedb nocreaterole`
	if u, err := url.Parse(serviceDSN()); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			stmt += ` password ` + literal(pw)
		}
	}
	if _, err := admin.Exec(ctx, stmt); err != nil {
		t.Fatalf("create role: %v", err)
	}
}

func applyFile(t testing.TB, ctx context.Context, dsn, path string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- path is built from the test's own location
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	conn := connect(t, dsn)
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, string(body)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

func connect(t testing.TB, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", redact(dsn), err)
	}
	return conn
}

func withDatabase(t testing.TB, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

func databaseName(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(u.Path, "/")
}

func fixturePath(t testing.TB, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// This file lives in <root>/test/harness.
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	return filepath.Join(root, "test", "fixtures", name)
}

func suffix(t testing.TB) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func literal(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// redact keeps a DSN out of test output.
func redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<dsn>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}
