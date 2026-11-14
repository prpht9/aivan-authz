//go:build integration

// Package harness builds a scratch database for integration tests: the hud
// fixture, the roles the grant matrix names, and the schema from aivan-hud's
// own migrations.
//
// It runs aivan-hud's migrations rather than a copy of the DDL. The DDL used to
// live in this repository and was embedded in the gate's binary; it lives in
// aivan-hud's history now (doc/schema-handover.md §2), and a test that applied a
// local copy would pass against a schema nobody deploys. A scratch database with
// no ruby on the host cannot be set up this way, and the harness skips rather
// than pretends.
package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServiceRole is the role the gate runs as. The grant matrix names it, so
// another name would leave the grants pointing at a role that does not exist.
const ServiceRole = "aivan_authz"

// CoreRole is the application's role: it reads devices and revokes through the
// definer function, and writes nothing in authz otherwise.
const CoreRole = "aivan_core"

// MigrationRole owns schemas public and authz and runs the migrations.
const MigrationRole = "aivan_migrations"

// DefaultSuperuser is where the integration tests expect a cluster they may
// create roles and databases on.
const DefaultSuperuser = "postgres://postgres@localhost/postgres"

// hudDir is the companion checkout whose migrations own the schema. It is a
// symlink in this repository's tree, recorded next to the README.
const hudDir = "aivan-hud"

// Env skips the test when no cluster is reachable.
func Env(t testing.TB) {
	t.Helper()
	if super := superuserDSN(); !reachable(super) {
		t.Skipf("no superuser database at %s; set AIVAN_TEST_SUPERUSER_URL", super)
	}
	if !hudMigrationsAvailable() {
		t.Skipf("no %s/db/migration with a Rakefile; the schema belongs to aivan-hud "+
			"(doc/schema-handover.md §2), so the integration suite cannot build one", hudDir)
	}
}

// Setup creates a scratch database with the application's schema, the roles the
// grant matrix names, and aivan-hud's migrations applied. It returns DSNs for
// the gate's credential and the migration credential. Cleanup is registered on
// t.
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

	ensureRoles(t, ctx, admin)

	// The application's schema and the authz schema both come from aivan-hud's
	// migrations, run the way the install runs them. There is no fixture: a
	// local copy of public.users would let a test pass against a shape the
	// application does not have.
	migrate(t, super)

	// On an install, `public` belongs to the application role and `authz` to
	// the migration role (README_HOME_INSTALL.md stage 1). The migration above
	// ran as the cluster superuser, so the ownership the install provisions is
	// applied here. Without it, a test that runs a console command as
	// aivan_core would fail on public.users rather than on the grant under
	// test.
	ownPublic(t, super)

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

// User is one person a test needs. Only the fields the gate reads have a
// meaning here; the rest are filled with values the application's own schema
// requires.
type User struct {
	ID       int64
	Username string
	Email    string
	Active   bool
}

// SeedUsers replaces the people and groups in a scratch database. It deletes
// first, in dependency order, so a test starts from a known set rather than
// from whatever the previous one left.
//
// The column list is the application's own: hud requires an email, both
// timestamps and a password digest, and a test that inserted only the three
// columns the gate reads would be testing a schema the application does not
// have.
func SeedUsers(t testing.TB, super string, users []User, groups map[int64]string, members map[int64][]int64) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`
		delete from authz.sessions;
		delete from authz.nonces;
		delete from authz.pending_enrollments;
		delete from authz.devices;
		delete from public.groups_users;
		delete from public.groups;
		delete from public.users;
	`)
	for _, u := range users {
		email := u.Email
		if email == "" {
			email = u.Username + "@example.invalid"
		}
		fmt.Fprintf(&b, `insert into public.users (id, email, username, active, password_digest, created_at, updated_at)
values (%d, %s, %s, %t, 'x', now(), now());`, u.ID, literal(email), literal(u.Username), u.Active)
	}
	for id, name := range groups {
		fmt.Fprintf(&b, `insert into public.groups (id, name, created_at, updated_at)
values (%d, %s, now(), now());`, id, literal(name))
	}
	for group, ids := range members {
		for _, u := range ids {
			fmt.Fprintf(&b, `insert into public.groups_users (group_id, user_id) values (%d, %d);`, group, u)
		}
	}
	Exec(t, super, b.String())
}

// Pool opens a pool as a superuser against dsn, for assertions that need to read
// a table the gate's credential may not read.
func Pool(t testing.TB, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
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

// ensureRoles creates the three roles the grant matrix names. The migration
// migration skips its grant half when any is missing, which would make every
// grant assertion in the suite vacuous, so they are created here.
func ensureRoles(t testing.TB, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	for _, role := range []string{ServiceRole, CoreRole, MigrationRole} {
		var exists bool
		if err := admin.QueryRow(ctx,
			`select exists (select 1 from pg_roles where rolname = $1)`, role).Scan(&exists); err != nil {
			t.Fatalf("check role %s: %v", role, err)
		}
		if exists {
			continue
		}
		stmt := `create role ` + ident(role) + ` login nosuperuser nocreatedb nocreaterole`
		if role == ServiceRole {
			if u, err := url.Parse(serviceDSN()); err == nil && u.User != nil {
				if pw, ok := u.User.Password(); ok {
					stmt += ` password ` + literal(pw)
				}
			}
		}
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("create role %s: %v", role, err)
		}
	}
}

// ownPublic applies the ownership and public-schema grants the install
// provisions (README_HOME_INSTALL.md stage 1). The migrations run as the cluster
// superuser in a test, so the half they cannot do on an install — public belongs
// to the application role — has to be applied here.
//
// Without it a console command run as aivan_core would fail on public.users, and
// a test would be measuring the harness rather than the grant under test.
func ownPublic(t testing.TB, super string) {
	t.Helper()
	Exec(t, super, `
		alter schema public owner to `+ident(CoreRole)+`;
		alter table public.users             owner to `+ident(CoreRole)+`;
		alter table public.groups            owner to `+ident(CoreRole)+`;
		alter table public.groups_users      owner to `+ident(CoreRole)+`;
		alter table public.schema_migrations owner to `+ident(CoreRole)+`;
		grant create on schema public to `+ident(CoreRole)+`;

		-- The operator role: it owns authz and the definer functions read
		-- public.users from inside them, so it holds the minimum on public.
		grant usage on schema public                  to `+ident(MigrationRole)+`;
		grant references on public.users              to `+ident(MigrationRole)+`;
		grant select (id, username, active) on public.users  to `+ident(MigrationRole)+` with grant option;
		grant select (id, name)             on public.groups to `+ident(MigrationRole)+` with grant option;
		grant select                        on public.groups_users to `+ident(MigrationRole)+` with grant option;

		-- The gate's read on the public side. It never sees password_digest.
		grant usage on schema public to `+ident(ServiceRole)+`;
		grant select (id, username, active) on public.users  to `+ident(ServiceRole)+`;
		grant select (id, name)             on public.groups to `+ident(ServiceRole)+`;
		grant select                        on public.groups_users to `+ident(ServiceRole)+`;
		revoke create on schema public from `+ident(ServiceRole)+`;
	`)
}

// Operator is the DSN a command that needs no application authority uses: the
// migration role, which owns `authz`. The CronJob and the break-glass admin
// commands run as this or as a superuser supplied at the terminal.
func Operator(t testing.TB, super string) string {
	t.Helper()
	return AsRole(t, super, MigrationRole)
}

// hudMigrationsAvailable reports whether this checkout can run hud's
// migrations: the directory exists, and the host has the ruby to run them.
func hudMigrationsAvailable() bool {
	root := repoRoot()
	if root == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, hudDir, "db", "migration")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, hudDir, "Rakefile")); err != nil {
		return false
	}
	_, err := exec.LookPath("bundle")
	return err == nil
}

// migrate runs `rake db:migrate` in the hud checkout as the migration role. The
// migrations guard every object with IF NOT EXISTS and CREATE OR REPLACE, so a
// fresh database and a repaired one take the same path.
//
// The connection goes over the unix socket when no host is in the DSN, because
// rake's own default is the socket, and a test cluster on localhost may not
// accept a password over TCP.
func migrate(t testing.TB, super string) {
	t.Helper()
	root := repoRoot()
	if root == "" {
		t.Fatal("cannot locate the repository root")
	}

	cmd := exec.Command("bundle", "exec", "rake", "db:migrate")
	cmd.Dir = filepath.Join(root, hudDir)
	cmd.Env = append(os.Environ(), "DATABASE_URL="+super)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("aivan-hud migrate: %v\n%s", err, out)
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

// repoRoot is the directory holding go.mod, found from this file's location.
func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// This file lives in <root>/test/harness.
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
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
