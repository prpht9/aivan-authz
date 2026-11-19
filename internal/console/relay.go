package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chris/aivan-authz/internal/servicekey"
)

// RelayDevice is the part of a device row aivan-approval needs: the identity the
// home already created, and the public half of the key the phone now holds.
//
// It carries no private key and no session. The relay stores a routing row, so
// these six fields are the whole of what crosses.
type RelayDevice struct {
	ID        string
	UserID    int64
	Kind      string
	Alg       string
	PublicKey []byte
	State     string
}

// RelayDeviceByID reads one device row. A device the home does not have is an
// error rather than an empty registration: an operator typing an id wants to
// know it matched nothing.
func RelayDeviceByID(ctx context.Context, pool *pgxpool.Pool, deviceID string) (RelayDevice, error) {
	var out RelayDevice
	if err := pool.QueryRow(ctx, `
select d.id::text, d.user_id, d.kind, d.alg, d.public_key, d.state
  from authz.devices d
 where d.id = $1`, deviceID).
		Scan(&out.ID, &out.UserID, &out.Kind, &out.Alg, &out.PublicKey, &out.State); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, fmt.Errorf("no device %s", deviceID)
		}
		return out, err
	}
	if out.State != "live" {
		return out, fmt.Errorf("device %s is %s; the relay registers live devices only", out.ID, out.State)
	}
	return out, nil
}

// ErrNotClaimed reports that a pending enrollment is still waiting for a phone.
var ErrNotClaimed = errors.New("console: enrollment not claimed yet")

// ClaimedDevice returns the device a pending record produced, or ErrNotClaimed
// while the record is still unspent.
//
// The record is read rather than the device id being remembered from the mint,
// because the mint does not know it: the gate chooses the id inside the claim's
// transaction, and the only durable link between the two is the record's
// claimed_device_id.
func ClaimedDevice(ctx context.Context, pool *pgxpool.Pool, recordID string) (RelayDevice, error) {
	var claimed *string
	err := pool.QueryRow(ctx, `
select claimed_device_id::text from authz.pending_enrollments where id = $1`, recordID).Scan(&claimed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RelayDevice{}, fmt.Errorf("no pending enrollment %s", recordID)
		}
		return RelayDevice{}, err
	}
	if claimed == nil {
		return RelayDevice{}, ErrNotClaimed
	}
	return RelayDeviceByID(ctx, pool, *claimed)
}

// WaitForClaim polls the pending record until a phone claims it or ctx ends.
//
// Polling is the honest shape here: the claim happens on the phone, at a moment
// this process cannot be told about, and the record is the one durable fact both
// sides share. The interval is slow enough that a wait costs the database
// nothing worth measuring and quick enough that an operator sees the next line
// as soon as the phone is done.
//
// A claimed record whose device is not live is returned as an error rather than
// waited on: a revoked row is a state the relay will refuse, and no amount of
// waiting changes it.
func WaitForClaim(ctx context.Context, pool *pgxpool.Pool, recordID string, interval time.Duration) (RelayDevice, error) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		device, err := ClaimedDevice(ctx, pool, recordID)
		switch {
		case err == nil:
			return device, nil
		case !errors.Is(err, ErrNotClaimed):
			return RelayDevice{}, err
		}

		select {
		case <-ctx.Done():
			return RelayDevice{}, fmt.Errorf("the enrollment was not claimed before the wait ended (%w)", ctx.Err())
		case <-ticker.C:
		}
	}
}

// WriteRelayDevice prints what was registered, in the order an operator checks
// it: the identity the relay holds, then the fingerprint of the key it stored.
func WriteRelayDevice(w io.Writer, d RelayDevice, relayURL string) error {
	_, err := fmt.Fprintf(w,
		"relay: %s\nregistered: %s (user %d, %s, %s)\nkey_fingerprint: %s\n",
		relayURL, d.ID, d.UserID, d.Kind, d.Alg, servicekey.Fingerprint(d.PublicKey))
	return err
}
