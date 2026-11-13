// Package console implements the operator commands that are not part of the
// request path: listing devices and revoking one.
//
// They run as the same service role the gate uses, so they hold no privilege a
// request could not. What makes them operator-only is that they are
// subcommands of the binary, not routes.
package console

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
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
// The column list is explicit because the service role holds column grants on
// public.users, not a table grant: select * would fail, and it should.
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

// Hook is a seam for the crash test. Production passes the zero value; the
// integration build's crash test sets AfterUpdate to kill the process between
// the two writes (D7).
type Hook struct {
	// AfterUpdate runs inside the transaction, after devices.revoked_at is set
	// and before sessions are deleted.
	AfterUpdate func(ctx context.Context, tx pgx.Tx) error
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

// Revoke sets revoked_at and deletes every session of the device in one
// transaction, then writes the audit row. A process that dies mid-way leaves
// the database with no partial state: PostgreSQL rolls back the whole
// transaction, and the next run repeats it (S5, D7).
//
// A device id that does not exist is an error: an operator typing an id wants
// to know it matched nothing.
func Revoke(ctx context.Context, pool *pgxpool.Pool, deviceID string, h Hook) (RevokeResult, error) {
	var res RevokeResult
	uuid, err := parseUUID(deviceID)
	if err != nil {
		return res, err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// The row lock makes the read and the write one decision even if a second
	// operator runs the command at the same time.
	var userID int64
	var origin string
	var revoked *time.Time
	if err := tx.QueryRow(ctx, `
select user_id, origin, revoked_at
  from authz.devices
 where id = $1
   for update`, uuid).Scan(&userID, &origin, &revoked); err != nil {
		if err == pgx.ErrNoRows {
			return res, fmt.Errorf("no device %s", deviceID)
		}
		return res, err
	}

	if _, err := tx.Exec(ctx,
		`update authz.devices set revoked_at = coalesce(revoked_at, now()) where id = $1`,
		uuid); err != nil {
		return res, err
	}

	if h.AfterUpdate != nil {
		if err := h.AfterUpdate(ctx, tx); err != nil {
			return res, err
		}
	}

	tag, err := tx.Exec(ctx, `delete from authz.sessions where device_id = $1`, uuid)
	if err != nil {
		return res, err
	}

	if _, err := tx.Exec(ctx, `
insert into authz.audit_log (user_id, device_id, host, route, decision, reason)
values ($1, $2, $3, 'console', 'revoke', 'device_revoked')`, userID, uuid, origin); err != nil {
		return res, err
	}

	if err := tx.Commit(ctx); err != nil {
		return res, err
	}

	return RevokeResult{
		DeviceID:       deviceID,
		UserID:         userID,
		Sessions:       tag.RowsAffected(),
		AlreadyRevoked: revoked != nil,
	}, nil
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
