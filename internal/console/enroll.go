package console

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/proof"
)

// EnrollTTL is how long a printed code may be claimed. It is short on purpose:
// the code crosses one screen to another, and a record that outlives a coffee
// break is a credential nobody is watching (spec §6.5).
const EnrollTTL = 15 * time.Minute

// KindBrowser is the one device kind a pending enrollment can produce in this
// phase. The column allows phone and tablet for a later phase that has a way to
// claim them.
const KindBrowser = "browser"

// EnrollOptions is one `authz-admin enroll-new` invocation.
type EnrollOptions struct {
	Username string
	Origin   string
	Kind     string
}

// EnrollResult is what the command prints and what a test asserts. The code is
// the only copy: only its digest is stored, so it cannot be recovered from the
// database and there is no --show.
type EnrollResult struct {
	RecordID string
	UserID   int64
	Username string
	Origin   string
	Kind     string
	Code     string
	Expires  time.Time
}

// Enroll mints one pending enrollment and returns the code exactly once.
//
// The operator is explicit here, unlike HTTP: an unknown user, an origin outside
// AIVAN_HOSTS and a duplicate live device are all refusals with a message and a
// non-zero exit. Each one closes a way to create a credential nobody meant to
// create (plan §5.7, spec §6.5).
func Enroll(ctx context.Context, pool *pgxpool.Pool, o EnrollOptions, hosts []string, operator string) (EnrollResult, error) {
	var out EnrollResult

	if out.Username = strings.TrimSpace(o.Username); out.Username == "" {
		return out, errors.New("--username must not be empty")
	}
	if err := normaliseKind(o.Kind, &o.Kind); err != nil {
		return out, err
	}
	// Phase F's claim endpoint accepts browser claims only: one static page,
	// and a page is a browser. A phone or tablet record would be a code with no
	// endpoint to spend it on, so the console refuses rather than printing one.
	if o.Kind != KindBrowser {
		return out, fmt.Errorf("--kind %s has no claim endpoint yet; "+
			"this phase enrolls %s devices only", o.Kind, KindBrowser)
	}
	// The origin is one of the hosts the gate serves, so a typo is refused here
	// rather than producing a record whose every claim is an origin mismatch.
	if o.Origin == "" {
		return out, errors.New("--origin is required")
	}
	if !contains(hosts, o.Origin) {
		return out, fmt.Errorf("--origin %q is not in AIVAN_HOSTS (%v)", o.Origin, hosts)
	}
	out.Origin, out.Kind = o.Origin, o.Kind

	// 16 bytes, displayed as Crockford base32 with a dash every four
	// characters. The display form is for a human to read across a desk; the
	// claim normalises it back before hashing.
	var raw [proof.EnrollCodeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return out, err
	}
	display := proof.EncodeEnrollCode(raw[:])
	normalised := proof.NormalizeEnrollCode(display)
	if !proof.ValidEnrollCode(normalised) {
		// Unreachable: the encoder emits exactly the alphabet the validator
		// checks. A failure here is a code that could never be claimed.
		return out, fmt.Errorf("generated code %q does not normalise to a valid code", display)
	}
	out.Code = display

	// The digest covers the normalised text, which is the value the claim
	// re-normalises from whatever was typed. Hashing the display form would
	// make a miscased code a different record.
	hash := proof.SHA256Sum([]byte(normalised))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := tx.QueryRow(ctx,
		`select id, username from public.users where username = $1 and active`,
		out.Username).Scan(&out.UserID, &out.Username); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, fmt.Errorf("no active user named %q", o.Username)
		}
		return out, err
	}

	// A live device of this kind means the person can already sign in on this
	// origin; another code would be a second way to hold the same slot, and the
	// partial unique index would refuse the claim at the end anyway.
	var existingDevice string
	err = tx.QueryRow(ctx, `
select id::text from authz.devices
 where user_id = $1 and origin = $2 and kind = $3 and revoked_at is null`,
		out.UserID, o.Origin, o.Kind).Scan(&existingDevice)
	if err == nil {
		return out, fmt.Errorf("user %q already has a live %s device on %s (%s); "+
			"end it with `authz-admin revoke --device %s` before minting another",
			out.Username, o.Kind, o.Origin, existingDevice, existingDevice)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}

	// An unclaimed record that has not expired is a code already in someone's
	// hand. Printing a second one would leave two live codes for one slot.
	var liveID string
	var liveExpiry time.Time
	err = tx.QueryRow(ctx, `
select id::text, expires_at from authz.pending_enrollments
 where user_id = $1 and origin = $2 and kind = $3
   and claimed_at is null and expires_at > now()`,
		out.UserID, o.Origin, o.Kind).Scan(&liveID, &liveExpiry)
	if err == nil {
		return out, fmt.Errorf("an unclaimed enrollment already exists for user %q on %s (%s), expiring %s; "+
			"wait for it to expire or revoke the record before minting another",
			out.Username, o.Origin, liveID, liveExpiry.UTC().Format(time.RFC3339))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}

	// An unclaimed record that has expired occupies the partial index's slot
	// but can never be claimed. Removing it keeps the index a live-record
	// guard without making an operator wait for a sweep.
	if _, err := tx.Exec(ctx, `
delete from authz.pending_enrollments
 where user_id = $1 and origin = $2 and kind = $3
   and claimed_at is null and expires_at <= now()`,
		out.UserID, o.Origin, o.Kind); err != nil {
		return out, err
	}

	var expiry time.Time
	if err := tx.QueryRow(ctx, `
insert into authz.pending_enrollments (user_id, origin, kind, code_hash, expires_at)
values ($1, $2, $3, $4, now() + $5)
returning id::text, expires_at`,
		out.UserID, o.Origin, o.Kind, hash[:],
		pgtype.Interval{Microseconds: EnrollTTL.Microseconds(), Valid: true},
	).Scan(&out.RecordID, &expiry); err != nil {
		// The partial index is the guard when two operators run at once.
		return out, fmt.Errorf("mint enrollment: %w", err)
	}
	out.Expires = expiry

	// The audit row names the operator's OS user and the record. The gate's
	// claim row names the device that consumed it, so an operator can see both
	// ends of one enrollment.
	if _, err := tx.Exec(ctx, `
insert into authz.audit_log (user_id, host, route, decision, reason, actor, subject_id)
values ($1, $2, 'console', 'enroll', 'minted', $3, $4)`,
		out.UserID, o.Origin, operator, out.RecordID); err != nil {
		return out, err
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

// WriteEnroll prints the code once, with the record and expiry it belongs to.
// There is no second path that prints it: the digest is all the database holds.
func WriteEnroll(w io.Writer, r EnrollResult) error {
	if _, err := fmt.Fprintf(w, "enrollment code: %s\n", r.Code); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "user: %s (id %d)\norigin: %s\nkind: %s\nrecord: %s\nexpires_at: %s\n\n"+
		"Enter the code at https://%s/__aivan/enroll within %s. It is shown once.\n",
		r.Username, r.UserID, r.Origin, r.Kind, r.RecordID,
		r.Expires.UTC().Format(time.RFC3339), r.Origin, time.Until(r.Expires).Round(time.Minute))
	return err
}

// operatorName is the label an audit row carries for a console action. It is
// the OS user that ran the command, not an authenticated identity: the console
// is a shell on the compute server, and the shell's account is what the
// operator can be held to.
func operatorName() string {
	if v := strings.TrimSpace(os.Getenv("SUDO_USER")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	return "unknown"
}

// OperatorName is the exported form, so the subcommand in cmd can pass the same
// value a test can compute.
func OperatorName() string { return operatorName() }

// normaliseKind applies the default and refuses a kind outside the column's
// check constraint, so a typo is a console error rather than a constraint
// violation at claim time.
func normaliseKind(raw string, out *string) error {
	switch raw {
	case "":
		*out = "browser"
	case "browser", "phone", "tablet":
		*out = raw
	default:
		return fmt.Errorf("--kind must be browser, phone or tablet, not %q", raw)
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
