// Command seeder prepares a database for the load test in test/load/verify.js.
//
// It does two things the load generator must not do, because doing either one
// per request would measure the wrong code:
//
//   - It generates a P-256 device key, inserts the public half as a device row,
//     and prints the private half as a JWK for the script. The accept path then
//     signs with a key the gate already trusts.
//   - It pre-fills authz.nonces with single-use nonces and writes their
//     plaintext to a JSON file. A nonce is hashed at rest, so only the seeder
//     can produce the pair; the script consumes them one per accepted request.
//
// It is an operator tool, not part of the gate: it writes authz.devices and
// authz.nonces with whatever libpq connection its environment names, which is
// the migration role or a superuser, and never the gate's own read-mostly role.
// The connection is PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE, exactly
// as psql reads them; -dsn is there for a caller that would rather pass a
// connection string outright.
//
// Usage:
//
//	PGUSER=aivan_migrations PGDATABASE=aivan_core \
//	  go run ./test/load/seed -user 1 -count 100000
//
// The two outputs are the device id and JWK (stdout, as shell assignments with
// -jwk-env), and the nonce file (default /tmp/aivan-nonces.json).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	if err := run(); err != nil {
		// The message may quote a driver error; a load tester's shell is not
		// the gate's log, but connection detail should still not be echoed.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dsn        = flag.String("dsn", "", "connection string; when empty, libpq's PG* environment is used")
		userID     = flag.Int64("user", 0, "user id the device belongs to")
		origin     = flag.String("origin", "aivan-hud.home.arpa", "origin the device is enrolled for")
		kind       = flag.String("kind", "tablet", "device kind; must not collide with a live device of the same user and origin")
		name       = flag.String("device", "aivan-loadtest", "device name, so the row is identifiable")
		count      = flag.Int("count", 100000, "how many nonces to pre-generate")
		noncesPath = flag.String("nonces", "/tmp/aivan-nonces.json", "where to write the plaintext nonces for the script")
		ttl        = flag.Duration("ttl", 4*time.Hour, "nonce lifetime; the run must finish inside it")
		hourAgo    = flag.Duration("issued", time.Hour, "how far in the past to stamp issued_at, so any run timestamp is after it")
		jwkEnv     = flag.Bool("jwk-env", false, "print AIVAN_LOAD_JWK=… instead of the bare JWK")
	)
	flag.Parse()

	if *userID == 0 {
		return fmt.Errorf("-user is required: the device must belong to an existing person")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y) // 65-byte uncompressed point

	deviceID, err := newUUID()
	if err != nil {
		return err
	}

	if _, err := conn.Exec(ctx, `
		insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
		values ($1, $2, $3, $4, $5, $6, 'es256')`,
		deviceID, *userID, *origin, *name, *kind, pub); err != nil {
		return fmt.Errorf("insert device: %w", err)
	}
	fmt.Printf("# device %s (user %d, origin %s, kind %s, alg es256)\n",
		deviceID, *userID, *origin, *kind)

	jwk, err := privateJWK(key)
	if err != nil {
		return err
	}
	if *jwkEnv {
		// The two variables the k6 script reads, in the form `eval` consumes.
		fmt.Printf("AIVAN_LOAD_DEVICE='%s'\n", deviceID)
		fmt.Printf("AIVAN_LOAD_JWK='%s'\n", jwk)
	} else {
		fmt.Println(jwk)
	}

	// The nonce pool: digest into the table, plaintext into the file.
	nonces := make([]string, 0, *count)
	batch := make([][]any, 0, nonceBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if _, err := conn.CopyFrom(ctx,
			pgx.Identifier{"authz", "nonces"},
			[]string{"nonce_hash", "device_id", "issued_at", "expires_at"},
			pgx.CopyFromRows(batch)); err != nil {
			return fmt.Errorf("copy nonces: %w", err)
		}
		batch = batch[:0]
		return nil
	}

	now := time.Now()
	issued := now.Add(-*hourAgo)
	expires := now.Add(*ttl)
	for i := 0; i < *count; i++ {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return fmt.Errorf("nonce entropy: %w", err)
		}
		sum := sha256.Sum256(raw[:])
		batch = append(batch, []any{sum[:], deviceID, issued, expires})
		nonces = append(nonces, base64.RawURLEncoding.EncodeToString(raw[:]))
		if len(batch) >= nonceBatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}

	body, err := json.Marshal(nonces)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*noncesPath, body, 0o600); err != nil {
		return fmt.Errorf("write nonces: %w", err)
	}
	fmt.Fprintf(os.Stderr, "seeded %d nonces for %s (issued %s, expires %s) into %s\n",
		len(nonces), deviceID, issued.Format(time.RFC3339), expires.Format(time.RFC3339), *noncesPath)
	return nil
}

// nonceBatchSize is how many rows one COPY sends. Large enough that 100k rows is
// twenty round trips, small enough that a failure names a small slice.
const nonceBatchSize = 5000

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(raw), nil
}

func formatUUID(raw [16]byte) string {
	const digits = "0123456789abcdef"
	var out [36]byte
	n := 0
	for i, c := range raw {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[n] = '-'
			n++
		}
		out[n] = digits[c>>4]
		out[n+1] = digits[c&0x0f]
		n += 2
	}
	return string(out[:])
}

// privateJWK renders the key as a JWK. P-256 coordinates are 32 bytes, left
// padded, base64url without padding: what WebCrypto's importKey expects.
func privateJWK(k *ecdsa.PrivateKey) (string, error) {
	field := func(v *big.Int) string {
		b := make([]byte, 32)
		v.FillBytes(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	j := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   field(k.X),
		"y":   field(k.Y),
		"d":   field(k.D),
	}
	body, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
