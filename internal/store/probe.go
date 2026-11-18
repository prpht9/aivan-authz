package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Refusal is the message an operator sees when the database role holds more
// privilege than the design allows. A gate that can write a device, read the
// audit log, or change a table is a misconfigured gate, and it refuses to start
// rather than serve.
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

// FixGrants is the remediation every privilege refusal names. The grants live
// in aivan-hud's migration history now, so the operator is sent there rather
// than to a file in this repo.
const FixGrants = "The service must run as aivan_authz with only the grants in " +
	"aivan-hud/doc/schema-ownership.md §4 (rake db:check_grants verifies them)."

// TxStarter is the part of pgxpool.Pool the probe needs.
type TxStarter interface {
	Begin(context.Context) (pgx.Tx, error)
}

// PrivilegeProbe checks the service credential against the grant matrix and
// rolls back. It runs at startup, before the listener opens. Any error is a
// refusal: a probe that cannot run proves nothing.
//
// It asserts absence as well as presence. A credential that can create or
// destroy a device, read the evidence of its own decisions, or approve anything
// is a credential a compromise could use, so the gate will not start holding
// one. The list is doc/schema-handover.md §6.
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

	// The schema the gate serves from must exist before anything else is
	// measured: a missing authz means the migrations have not run, and every
	// later check would fail with a message about a grant instead.
	if err := probeSchema(ctx, tx); err != nil {
		return err
	}

	// PostgreSQL aborts a transaction on the first error, and a passing
	// outcome below is an error, so each assertion gets its own savepoint.
	for _, a := range absenceAssertions {
		if err := probeDenied(ctx, tx, a); err != nil {
			return err
		}
	}
	for _, a := range presenceAssertions {
		if err := probeHolds(ctx, tx, a); err != nil {
			return err
		}
	}
	return nil
}

// probeSchema proves the gate's schema exists and that the gate cannot create
// objects in it.
func probeSchema(ctx context.Context, tx pgx.Tx) error {
	var canCreate bool
	if err := tx.QueryRow(ctx,
		`select has_schema_privilege('public', 'CREATE')`).Scan(&canCreate); err != nil {
		return &Refusal{
			What: "could not measure schema privileges.",
			Fix:  "Apply aivan-hud's migrations (rake db:migrate) as aivan_migrations.",
			Err:  err,
		}
	}
	if canCreate {
		return &Refusal{
			What: "database role can create objects in schema public.",
			Fix:  FixGrants,
		}
	}

	var canCreateAuthz bool
	if err := tx.QueryRow(ctx,
		`select has_schema_privilege('authz', 'CREATE')`).Scan(&canCreateAuthz); err != nil {
		return &Refusal{
			What: "could not measure privileges on schema authz.",
			Fix:  "Apply aivan-hud's migrations (rake db:migrate) as aivan_migrations.",
			Err:  err,
		}
	}
	if canCreateAuthz {
		return &Refusal{
			What: "database role can create objects in schema authz.",
			Fix:  FixGrants,
		}
	}
	return nil
}

// assertion is one privilege the probe measures. what names it in an operator's
// terms; run is the statement, or the catalog question, that measures it.
type assertion struct {
	what string
	run  func(context.Context, pgx.Tx) error
}

// absenceAssertions is everything the gate must not hold. A statement that
// succeeds is the refusal; a denial is the pass.
var absenceAssertions = []assertion{
	{
		what: "can insert into public.users",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `insert into public.users (id, username) values (-1, 'privilege-probe')`)
			return err
		},
	},
	{
		what: "can read public.users.password_digest",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `select password_digest from public.users limit 1`)
			return err
		},
	},
	{
		what: "can insert into authz.devices",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
values (gen_random_uuid(), -1, 'probe', 'probe', 'browser', '\x00', 'ed25519')`)
			return err
		},
	},
	{
		what: "can revoke a device, by updating authz.devices.revoked_at",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `update authz.devices set revoked_at = now()`)
			return err
		},
	},
	{
		what: "can update authz.devices.public_key",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `update authz.devices set public_key = '\x00'`)
			return err
		},
	},
	{
		what: "can delete from authz.devices",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `delete from authz.devices`)
			return err
		},
	},
	{
		// The evidence is written and never read: a compromised gate cannot
		// scrub the record of its own decisions (doc/schema-ownership.md §7).
		what: "can read authz.audit_log",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `select decision from authz.audit_log limit 1`)
			return err
		},
	},
	{
		what: "can insert into authz.approvals",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
insert into authz.approvals (request_id, service_id, subject_user_id, resource,
                             permissions, request_hash, request_body, approver_requirement)
values (gen_random_uuid(), gen_random_uuid(), -1, 'probe', '{}', '\x00', '{}', 'admin')`)
			return err
		},
	},
	{
		what: "can update authz.approvals",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `update authz.approvals set status = 'approved'`)
			return err
		},
	},
	{
		what: "can insert into authz.services",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
insert into authz.services (name, public_key, alg) values ('privilege-probe', '\x00', 'ed25519')`)
			return err
		},
	},
	{
		// Revocation is a hud action: a compromised gate that could revoke
		// every device would be a denial of service on the whole system.
		what: "can execute authz.revoke_device",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `select * from authz.revoke_device(gen_random_uuid(), 'privilege-probe')`)
			return err
		},
	},
	{
		// Enrollment is spendable only through the definer function; a direct
		// insert into pending_enrollments would be minting without an operator.
		what: "can insert into authz.pending_enrollments",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
insert into authz.pending_enrollments (user_id, origin, kind, code_hash, expires_at)
values (-1, 'probe', 'browser', '\x00', now() + interval '1 minute')`)
			return err
		},
	},
	{
		what: "can create a table, by writing DDL",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `create table public.privilege_probe (id int)`)
			return err
		},
	},
}

// presenceAssertions is everything the gate must hold, as the statements it
// actually runs. Each one is the shape of a statement the gate issues, so a
// grant that was revoked fails here at startup rather than on a live request.
var presenceAssertions = []assertion{
	{
		what: "can read authz.devices",
		run: func(ctx context.Context, tx pgx.Tx) error {
			// state is in the list because every liveness check reads it: a
			// missing column grant would otherwise fail the first request
			// rather than the start.
			_, err := tx.Exec(ctx, `
select id, user_id, origin, kind, state, public_key, alg, created_at, last_seen_at, revoked_at
  from authz.devices limit 1`)
			return err
		},
	},
	{
		what: "can read authz.services",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
select id, name, public_key, alg, created_at, retired_at from authz.services limit 1`)
			return err
		},
	},
	{
		what: "can read authz.approvals",
		run: func(ctx context.Context, tx pgx.Tx) error {
			// approver_requirement is in the list because ApprovalHashSQL names
			// it: a missing column grant fails here at startup rather than on the
			// first decision (aivan-hud 202611170310).
			_, err := tx.Exec(ctx, `
select id, subject_user_id, resource, permissions, status, expires_at, consumed_at,
       request_hash, approver_requirement
  from authz.approvals limit 1`)
			return err
		},
	},
	{
		// The column grant, not a table UPDATE: stamping last_seen_at is the
		// only write the gate makes to a device row.
		what: "can stamp authz.devices.last_seen_at",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`update authz.devices set last_seen_at = last_seen_at where false`)
			return err
		},
	},
	{
		what: "can append to authz.audit_log",
		run: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
insert into authz.audit_log (user_id, host, route, decision, reason)
values (-1, 'probe', 'probe', 'probe', 'probe')`)
			return err
		},
	},
	{
		what: "can drive authz.nonces",
		run: func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `
insert into authz.nonces (nonce_hash, device_id, expires_at)
values ('\x00', gen_random_uuid(), now() + interval '1 minute')`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `select count(*) from authz.nonces`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `delete from authz.nonces where false`)
			return err
		},
	},
	{
		what: "can drive authz.sessions",
		run: func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`update authz.sessions set idle_expires_at = idle_expires_at where false`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `delete from authz.sessions where false`)
			return err
		},
	},
}

// probeDenied asserts that one statement is denied with insufficient_privilege.
// A denial is the pass; a statement that succeeds is a refusal; any other
// error means the environment is wrong in a different way, and says so.
func probeDenied(ctx context.Context, tx pgx.Tx, a assertion) error {
	probeErr, err := probeInSavepoint(ctx, tx, a)
	if err != nil {
		return err
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
		What: "privilege probe could not prove that the role cannot " + strings.TrimPrefix(a.what, "can ") + ".",
		Fix: "Expected SQLSTATE 42501 (insufficient_privilege). Any other error means the schema " +
			"does not match the design: check that aivan-hud's migrations have run, and that the " +
			"service role is aivan_authz.",
		Err: probeErr,
	}
}

// probeHolds asserts that one statement runs. A denial here names the grant the
// gate is missing, which is what an operator needs to fix it.
func probeHolds(ctx context.Context, tx pgx.Tx, a assertion) error {
	probeErr, err := probeInSavepoint(ctx, tx, a)
	if err != nil {
		return err
	}
	if probeErr == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(probeErr, &pgErr) && pgErr.Code == insufficientPrivilege {
		return &Refusal{
			What: "database role cannot " + strings.TrimPrefix(a.what, "can ") + ".",
			Fix:  FixGrants,
			Err:  probeErr,
		}
	}
	return &Refusal{
		What: "privilege probe could not run the statement for " + a.what + ".",
		Fix: "Expected either success or SQLSTATE 42501. Any other error means the schema " +
			"does not match the design: check that aivan-hud's migrations have run.",
		Err: probeErr,
	}
}

// probeInSavepoint runs one assertion and rolls back to the savepoint, so a
// failed statement does not abort the transaction the other assertions use. It
// returns the assertion's own error and, separately, a probe failure.
func probeInSavepoint(ctx context.Context, tx pgx.Tx, a assertion) (assertionErr, probeErr error) {
	if _, err := tx.Exec(ctx, `savepoint probe`); err != nil {
		return nil, &Refusal{
			What: "could not create the probe savepoint.",
			Fix:  "The service role must be able to open a transaction with savepoints.",
			Err:  err,
		}
	}
	probeErr = a.run(ctx, tx)
	if _, err := tx.Exec(ctx, `rollback to savepoint probe`); err != nil {
		return nil, &Refusal{
			What: "could not roll back the probe savepoint.",
			Fix:  "The service role must be able to open a transaction with savepoints.",
			Err:  err,
		}
	}
	return probeErr, nil
}
