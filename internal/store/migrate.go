package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// migrationLockKey is the pg_advisory_lock key that serialises migrate runs.
// Any constant works; this one is "aivz".
const migrationLockKey int64 = 0x6169767a

// Migration is one embedded SQL file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrations returns the embedded migrations ordered by version.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("read embedded schema: %w", err)
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("schema file %q has no version prefix", e.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("schema file %q has a non-numeric version: %w", e.Name(), err)
		}
		body, err := schemaFS.ReadFile("schema/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read schema file %q: %w", e.Name(), err)
		}
		out = append(out, Migration{Version: version, Name: e.Name(), SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("two schema files share version %d", out[i].Version)
		}
	}
	return out, nil
}

// Applied reports whether each migration version is recorded. A database with
// no authz schema has applied none.
func Applied(ctx context.Context, pool *pgxpool.Pool) (map[int]bool, error) {
	var exists bool
	if err := pool.QueryRow(ctx,
		`select to_regclass('authz.schema_migrations') is not null`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("probe schema_migrations: %w", err)
	}
	applied := map[int]bool{}
	if !exists {
		return applied, nil
	}
	rows, err := pool.Query(ctx, `select version from authz.schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// Migrate applies every embedded migration that is not yet recorded. Each
// migration runs in its own transaction and is recorded in the same
// transaction, so a failure leaves no half-applied version. An advisory lock
// keeps two concurrent runs from interleaving.
//
// It returns the versions it applied, in order.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]int, error) {
	migrations, err := Migrations()
	if err != nil {
		return nil, err
	}

	// The lock is session-scoped, so it lives on one dedicated connection.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := conn.Exec(lockCtx, `select pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return nil, fmt.Errorf("take migration lock: %w", err)
	}
	defer func() {
		// Best effort: the connection returning to the pool releases a
		// session lock anyway.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `select pg_advisory_unlock($1)`, migrationLockKey)
	}()

	applied, err := Applied(ctx, pool)
	if err != nil {
		return nil, err
	}

	var done []int
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return done, err
		}
		done = append(done, m.Version)
	}
	return done, nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migration %s: begin: %w", m.Name, err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("migration %s: %w", m.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`insert into authz.schema_migrations (version) values ($1)`, m.Version); err != nil {
		return fmt.Errorf("migration %s: record version: %w", m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migration %s: commit: %w", m.Name, err)
	}
	return nil
}
