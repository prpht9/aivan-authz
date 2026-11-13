package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Refusal is the message an operator sees when the database role holds more
// privilege than the design allows. S16 and S20 are enforced here so a
// misconfigured deploy fails loudly instead of quietly holding more access
// than the code assumes.
type Refusal struct {
	// What: the privilege that was found, or the check that could not run.
	What string
	// Fix: what the operator should do instead.
	Fix string
	// Err: the underlying error, if any. The DSN is never part of it.
	Err error
}

func (r *Refusal) Error() string {
	var b strings.Builder
	b.WriteString("refusing to start: ")
	b.WriteString(r.What)
	b.WriteString("\n")
	b.WriteString(r.Fix)
	if r.Err != nil {
		b.WriteString("\nunderlying error: ")
		b.WriteString(r.Err.Error())
	}
	return b.String()
}

func (r *Refusal) Unwrap() error { return r.Err }

// insufficientPrivilege is PostgreSQL's SQLSTATE for a denied grant.
const insufficientPrivilege = "42501"

// FixGrants is the remediation every privilege refusal names.
const FixGrants = "The service must run as a role with only the grants in 0002_grants.sql."

// TxStarter is the part of pgxpool.Pool the probe needs.
type TxStarter interface {
	Begin(context.Context) (pgx.Tx, error)
}

// PrivilegeProbe checks the service credential against three assertions and
// rolls back. It runs at startup, before the listener opens. Any error is a
// refusal: a probe that cannot run proves nothing.
func PrivilegeProbe(ctx context.Context, pool TxStarter) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return &Refusal{
			What: "could not open the probe transaction.",
			Fix:  "The service must be able to reach the database as the aivan_authz role.",
			Err:  err,
		}
	}
	// The probe only ever observes; nothing it does may survive.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// 1. No CREATE on schema public.
	var canCreate bool
	if err := tx.QueryRow(ctx,
		`select has_schema_privilege('public', 'CREATE')`).Scan(&canCreate); err != nil {
		return &Refusal{
			What: "could not measure schema privileges.",
			Fix:  "Apply the grants in internal/store/schema/0002_grants.sql to the service role.",
			Err:  err,
		}
	}
	if canCreate {
		return &Refusal{
			What: "database role can create objects in schema public.",
			Fix:  FixGrants,
		}
	}

	// PostgreSQL aborts a transaction on the first error, and the passing
	// outcome below is an error, so each assertion gets its own savepoint.
	if err := probeDenied(ctx, tx, assertion{
		what: "can insert into public.users",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `insert into public.users (id, username) values (-1, 'privilege-probe')`)
			return err
		},
	}); err != nil {
		return err
	}

	return probeDenied(ctx, tx, assertion{
		what: "can read public.users.password_digest",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `select password_digest from public.users limit 1`)
			return err
		},
	})
}

type assertion struct {
	// what names the privilege in an operator's terms, e.g. "can insert into
	// public.users".
	what string
	run  func(context.Context, pgx.Tx) error
}

// probeDenied asserts that one statement is denied with insufficient_privilege.
// A denial is the pass; a statement that succeeds is a refusal; any other
// error means the environment is wrong in a different way, and says so.
func probeDenied(ctx context.Context, tx pgx.Tx, a assertion) error {
	if _, err := tx.Exec(ctx, `savepoint probe`); err != nil {
		return &Refusal{
			What: "could not create the probe savepoint.",
			Fix:  "The service role must be able to open a transaction with savepoints.",
			Err:  err,
		}
	}
	probeErr := a.run(ctx, tx)
	if _, err := tx.Exec(ctx, `rollback to savepoint probe`); err != nil {
		return &Refusal{
			What: "could not roll back the probe savepoint.",
			Fix:  "The service role must be able to open a transaction with savepoints.",
			Err:  err,
		}
	}

	if probeErr == nil {
		return &Refusal{
			What: "database role " + a.what + ".",
			Fix:  FixGrants,
		}
	}
	var pgErr *pgconn.PgError
	if errors.As(probeErr, &pgErr) && pgErr.Code == insufficientPrivilege {
		return nil
	}
	return &Refusal{
		What: "privilege probe could not prove that " + a.what + " is refused.",
		Fix: "Expected SQLSTATE 42501 (insufficient_privilege). Any other error means the schema " +
			"does not match the design: check that public.users exists with an id, a username " +
			"and a password_digest column, and that the service role is aivan_authz.",
		Err: probeErr,
	}
}
