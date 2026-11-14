// Package console implements the operator commands that are not part of the
// request path: minting an enrollment, listing devices, revoking one, purging
// expired rows, and registering a service key.
//
// They live in cmd/authz-admin and reach the database with the operator
// credential. None of them is compiled into the gate's binary, so a process
// that is compromised in the pod cannot mint, revoke, or enumerate anything
// (doc/schema-handover.md §4).
package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Device is one row of list-devices.
type Device struct {
	ID       string
	Origin   string
	Kind     string
	Name     string
	Alg      string
	Created  time.Time
	LastSeen *time.Time
	Revoked  *time.Time
}

// ListDevices returns the devices of one user, most recently created first.
//
// The column list is explicit because a role may hold column grants rather than
// a table grant: select * would fail, and it should.
func ListDevices(ctx context.Context, pool *pgxpool.Pool, username string) ([]Device, error) {
	rows, err := pool.Query(ctx, `
select d.id::text, d.origin, d.kind, d.name, d.alg,
       d.created_at, d.last_seen_at, d.revoked_at
  from authz.devices d
  join public.users u on u.id = d.user_id
 where u.username = $1
 order by d.created_at desc, d.kind`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Origin, &d.Kind, &d.Name, &d.Alg,
			&d.Created, &d.LastSeen, &d.Revoked); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// WriteDevices prints the table list-devices shows. Times are rendered in the
// local zone of the machine running the command, and an absent time is "-".
func WriteDevices(w io.Writer, devices []Device) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tORIGIN\tKIND\tNAME\tALG\tCREATED\tLAST_SEEN\tREVOKED"); err != nil {
		return err
	}
	for _, d := range devices {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.ID, d.Origin, d.Kind, d.Name, d.Alg,
			stamp(&d.Created), stamp(d.LastSeen), stamp(d.Revoked)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func stamp(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Local().Format(time.RFC3339)
}

// RevokeResult is what the command prints.
type RevokeResult struct {
	DeviceID string
	UserID   int64
	Sessions int64
	// AlreadyRevoked reports that revoked_at was already set. The sessions are
	// still deleted in that case: it costs nothing, and it repairs a device
	// whose first revoke found no session table access.
	AlreadyRevoked bool
}

// Revoke revokes one device and deletes every session it holds by calling
// authz.revoke_device(). The function is the transaction: the row lock, the
// revoked_at update, the session delete and the audit row commit or roll back
// together, so a process that dies mid-way leaves no partial state (S5, D7).
//
// The gate holds no EXECUTE on this function. Revocation is a hud action, with
// this command as the break-glass path for when hud is down; a compromised gate
// that could revoke every device would be a denial of service on the whole
// system.
//
// A device id that does not exist is an error: an operator typing an id wants
// to know it matched nothing.
func Revoke(ctx context.Context, pool *pgxpool.Pool, deviceID, actor string) (RevokeResult, error) {
	var res RevokeResult
	uuid, err := parseUUID(deviceID)
	if err != nil {
		return res, err
	}
	if actor == "" {
		actor = OperatorName()
	}

	var (
		sessions int32
		was      bool
	)
	if err := pool.QueryRow(ctx,
		`select user_id, sessions_killed, was_revoked
		   from authz.revoke_device($1, $2)`, uuid, actor).
		Scan(&res.UserID, &sessions, &was); err != nil {
		if pgCode(err) == "P0002" {
			return res, fmt.Errorf("no device %s", deviceID)
		}
		return res, err
	}

	res.DeviceID = deviceID
	res.Sessions = int64(sessions)
	res.AlreadyRevoked = was
	return res, nil
}

// PurgeCounts is what one purge removed.
type PurgeCounts struct {
	Nonces   int64
	Sessions int64
}

// PurgeGrace is how long an expired nonce or idle session is kept past its
// expiry. A row deleted while a request is still racing its own
// `delete ... returning` would make the request fail as a replay; the grace
// removes that race without keeping an expired row usable, because the verify
// statement's own predicate already refuses it.
const PurgeGrace = time.Hour

// Purge removes expired nonces and idle or absolutely expired sessions in one
// transaction. Both statements commit or neither does: a failure of the second
// must not leave the first applied and the log line claiming both counts.
//
// It is safe to run from more than one CronJob at once. The statements are
// idempotent deletes with their own predicates, so a concurrent pass removes
// rows the other has not, and both report what they themselves removed.
//
// The gate holds DML on both tables — a session ends with a delete and a nonce
// is spent by one — but it no longer purges: the scheduled pass is administration
// and runs here, outside the pod, so the gate's serve path has no timer that
// changes rows (doc/schema-handover.md §5).
const (
	PurgeNonceSQL = `delete from authz.nonces where expires_at < now() - interval '1 hour'`

	PurgeSessionsSQL = `
delete from authz.sessions
 where idle_expires_at < now() - interval '1 hour'
    or absolute_expires_at < now()`
)

func Purge(ctx context.Context, pool *pgxpool.Pool) (PurgeCounts, error) {
	var counts PurgeCounts

	tx, err := pool.Begin(ctx)
	if err != nil {
		return counts, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	tag, err := tx.Exec(ctx, PurgeNonceSQL)
	if err != nil {
		return PurgeCounts{}, err
	}
	counts.Nonces = tag.RowsAffected()

	if tag, err = tx.Exec(ctx, PurgeSessionsSQL); err != nil {
		return PurgeCounts{}, err
	}
	counts.Sessions = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return PurgeCounts{}, err
	}
	return counts, nil
}

// Service is one row of list-services.
type Service struct {
	ID      string
	Name    string
	Alg     string
	Created time.Time
	Retired *time.Time
}

// RegisterService adds a service identity, which is the key a component signs
// approval requests with. The private half never reaches the cluster: an
// operator generates it on a workstation and passes only the public half here.
//
// Registering a name that already exists with a retired_at set is a rotation: it
// clears retired_at and installs the new key, which is why this is an upsert
// rather than an insert. A name that is live is refused, because replacing a
// key under a name that is in use would be a silent credential swap.
func RegisterService(ctx context.Context, pool *pgxpool.Pool, name, alg string, publicKey []byte) (Service, error) {
	var out Service
	if name == "" {
		return out, fmt.Errorf("--name must not be empty")
	}
	if alg != "ed25519" && alg != "es256" {
		return out, fmt.Errorf("--alg must be ed25519 or es256, not %q", alg)
	}
	if len(publicKey) == 0 {
		return out, fmt.Errorf("the public key is empty")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var live bool
	err = tx.QueryRow(ctx,
		`select retired_at is null from authz.services where name = $1`, name).Scan(&live)
	switch {
	case err == nil && live:
		return out, fmt.Errorf("service %q already has a live key; retire it first, or "+
			"use a new name", name)
	case err != nil && err != pgx.ErrNoRows:
		return out, err
	}

	if err := tx.QueryRow(ctx, `
insert into authz.services (name, public_key, alg)
values ($1, $2, $3)
on conflict (name) do update
   set public_key = excluded.public_key,
       alg        = excluded.alg,
       retired_at = null
returning id::text, name, alg, created_at, retired_at`,
		name, publicKey, alg).Scan(&out.ID, &out.Name, &out.Alg, &out.Created, &out.Retired); err != nil {
		return out, err
	}

	if _, err := tx.Exec(ctx, `
insert into authz.audit_log (host, route, decision, reason, actor, subject_id)
values ('console', 'service', 'register', 'service_registered', $1, $2)`,
		OperatorName(), out.ID); err != nil {
		return out, err
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

// RetireService sets retired_at so signatures made before this moment can still
// be explained, and no new one is accepted. It is idempotent: retiring twice
// keeps the first timestamp.
func RetireService(ctx context.Context, pool *pgxpool.Pool, name string) (Service, error) {
	var out Service
	if name == "" {
		return out, fmt.Errorf("--name must not be empty")
	}

	err := pool.QueryRow(ctx, `
update authz.services
   set retired_at = coalesce(retired_at, now())
 where name = $1
returning id::text, name, alg, created_at, retired_at`, name).
		Scan(&out.ID, &out.Name, &out.Alg, &out.Created, &out.Retired)
	if err == pgx.ErrNoRows {
		return out, fmt.Errorf("no service named %q", name)
	}
	return out, err
}

// ListServices returns every registered service, newest first, retired ones
// included so the table is the history rather than the current set.
func ListServices(ctx context.Context, pool *pgxpool.Pool) ([]Service, error) {
	rows, err := pool.Query(ctx, `
select id::text, name, alg, created_at, retired_at
  from authz.services order by created_at desc, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.ID, &s.Name, &s.Alg, &s.Created, &s.Retired); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WriteServices prints the table list-services shows.
func WriteServices(w io.Writer, services []Service) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tNAME\tALG\tCREATED\tRETIRED"); err != nil {
		return err
	}
	for _, s := range services {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Name, s.Alg, s.Created.Local().Format(time.RFC3339), stamp(s.Retired)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// pgCode returns a PostgreSQL SQLSTATE, or "" when the error carries none.
func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// parseUUID accepts the canonical form only, the same one the wire uses.
func parseUUID(s string) (pgtype.UUID, error) {
	var out pgtype.UUID
	if len(s) != 36 {
		return out, fmt.Errorf("%q is not a canonical UUID", s)
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return out, fmt.Errorf("%q is not a canonical UUID", s)
			}
			continue
		}
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return out, fmt.Errorf("%q is not a canonical UUID", s)
		}
		out.Bytes[n/2] <<= 4
		out.Bytes[n/2] |= v
		n++
	}
	out.Valid = true
	return out, nil
}
