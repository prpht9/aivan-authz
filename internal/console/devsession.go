//go:build devtools

package console

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/gate"
	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
)

// DevSessionOptions is one `authz dev-session` invocation.
type DevSessionOptions struct {
	Username string
	Origin   string
	Kind     string
	Alg      string
	Name     string

	// Idle and Max are the session lifetimes. Zero means the package
	// defaults, which are the values the deployment uses.
	Idle time.Duration
	Max  time.Duration
}

// DevSession is what the command prints. The token is the only copy: only its
// digest is stored, so it cannot be recovered from the database.
type DevSession struct {
	DeviceID   string
	UserID     int64
	Username   string
	Cookie     string
	IdleExpiry time.Time
	MaxExpiry  time.Time
}

// MintDevSession enrolls a throwaway device and mints one cookie for it.
//
// This exists so Phase E can exercise the proxy loop before enrollment exists
// (Phase F). It is compiled into a separate `devtools` build only, and it never
// ships in the image. The device has no private key it can prove with: the
// cookie is the whole credential, which is exactly the affordance being given
// away, so it must not survive Phase F.
func MintDevSession(ctx context.Context, pool *pgxpool.Pool, o DevSessionOptions) (DevSession, error) {
	var (
		out DevSession
		err error
	)
	if out.Username, err = normaliseUsername(o.Username); err != nil {
		return out, err
	}
	if err = normaliseKind(o.Kind, &o.Kind); err != nil {
		return out, err
	}
	if o.Alg == "" {
		o.Alg = string(proof.AlgorithmEd25519)
	}
	if !proof.Supported(o.Alg) {
		return out, fmt.Errorf("--alg must be ed25519 or es256, not %q", o.Alg)
	}
	if o.Name == "" {
		o.Name = "console test"
	}
	if o.Idle == 0 {
		o.Idle = gate.DefaultSessionIdle
	}
	if o.Max == 0 {
		o.Max = gate.DefaultSessionMax
	}

	publicKey, err := generatePublicKey(o.Alg)
	if err != nil {
		return out, err
	}

	var deviceID [16]byte
	if _, err := rand.Read(deviceID[:]); err != nil {
		return out, err
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return out, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := proof.SHA256Sum([]byte(token))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := tx.QueryRow(ctx, `
select id, username from public.users where username = $1 and active`,
		out.Username).Scan(&out.UserID, &out.Username); err != nil {
		if err == pgx.ErrNoRows {
			return out, fmt.Errorf("no active user named %q", o.Username)
		}
		return out, err
	}

	device := pgtype.UUID{Bytes: deviceID, Valid: true}
	if _, err := tx.Exec(ctx, `
insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
values ($1, $2, $3, $4, $5, $6, $7)`,
		device, out.UserID, o.Origin, o.Name, o.Kind, publicKey, o.Alg); err != nil {
		// The partial unique index is the one refusal an operator will hit
		// when repeating a test, so it names the way out.
		return out, fmt.Errorf("enroll device: %w (one live device per person, origin and kind; "+
			"end an earlier one with `authz revoke --device <id>` or run `authz list-devices --username %s`)",
			err, out.Username)
	}

	// The same statement the mint endpoint uses, so the row this writes is the
	// row the gate reads: nothing here is a second way to be a session.
	if err := tx.QueryRow(ctx, store.SessionMintSQL,
		hash[:], device, o.Origin,
		pgtype.Interval{Microseconds: o.Idle.Microseconds(), Valid: true},
		pgtype.Interval{Microseconds: o.Max.Microseconds(), Valid: true},
	).Scan(&out.IdleExpiry, &out.MaxExpiry); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}

	out.DeviceID = proof.FormatDeviceID(deviceID)
	out.Cookie = gate.SessionCookieHeader(token)
	return out, nil
}

// WriteDevSession prints the command's output. The cookie line is first and
// shaped so `grep Set-Cookie | cut -d' ' -f2` yields a value `curl -b` accepts.
func WriteDevSession(w io.Writer, s DevSession) error {
	if _, err := fmt.Fprintf(w, "Set-Cookie: %s\n", s.Cookie); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "device: %s\nuser: %s (id %d)\nidle_expires_at: %s\nabsolute_expires_at: %s\n",
		s.DeviceID, s.Username, s.UserID,
		s.IdleExpiry.UTC().Format(time.RFC3339), s.MaxExpiry.UTC().Format(time.RFC3339))
	return err
}

func normaliseUsername(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("--username must not be empty")
	}
	// The wire contract is the same one the gate enforces: a username that
	// cannot be a header value is not a device identity.
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '@', c == '-':
		default:
			return "", fmt.Errorf("--username %q has a character that cannot be a header value", name)
		}
	}
	return name, nil
}

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

// generatePublicKey makes a key of the requested algorithm. The private half is
// discarded: this device can hold a cookie, and cannot sign, which is the
// difference between a testing affordance and a credential.
func generatePublicKey(alg string) ([]byte, error) {
	switch proof.Algorithm(alg) {
	case proof.AlgorithmEd25519:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return pub, nil
	case proof.AlgorithmES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return elliptic.Marshal(elliptic.P256(), priv.X, priv.Y), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}
