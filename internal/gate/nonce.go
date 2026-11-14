package gate

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/store"
)

// NonceTableCap is the row count above which the nonce endpoint refuses. The
// endpoint is unauthenticated, so an unbounded table is a denial of service the
// design would hand an attacker (spec §5.1.1).
const NonceTableCap = 100_000

// The nonce cap is measured on CapInterval in maintenance.go: the handler reads
// the cached answer rather than counting per request.

// nonceResponse is the whole body of a successful nonce issue.
type nonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

// Nonce issues a single-use nonce for a claimed device id.
//
// It always succeeds for a syntactically valid id, whether or not the device
// exists (S14). There is no read of authz.devices on this path: the binding is
// enforced by the verify statement, where the device row has to match. That is
// what keeps this endpoint from being a device-existence oracle.
func (g *Gate) Nonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		g.refuse(w, r, http.StatusMethodNotAllowed, ReasonMethodNotAllowed, forwarded{}, "nonce is POST")
		return
	}

	if !g.limiter.Allow(g.sourceIP(r)) {
		g.refuse(w, r, http.StatusTooManyRequests, ReasonRateLimited, forwarded{}, "nonce rate limited")
		return
	}

	// The table cap is checked before the insert, so a full table costs no
	// write. Maintenance is once a minute whether it is driven from here or
	// from RunMaintenance; the handler runs it so the cap also holds on a
	// service that receives no ticker, which is what the tests build.
	if full, err := g.maintain(r.Context()); err != nil {
		g.databaseError(w, r, forwarded{}, err)
		return
	} else if full {
		g.refuse(w, r, http.StatusServiceUnavailable, ReasonNonceTableFull, forwarded{}, "nonce table at cap")
		return
	}

	deviceID, err := readNonceRequest(r)
	if err != nil {
		g.refuse(w, r, http.StatusBadRequest, ReasonBadRequest, forwarded{}, "nonce request body")
		return
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		g.databaseError(w, r, forwarded{}, err)
		return
	}
	nonce := encodeNonce(raw[:])
	hash := proof.SHA256Sum(raw[:])

	var expiresAt time.Time
	if err := g.pool.QueryRow(r.Context(), store.StmtNonce, hash[:], deviceID,
		pgtype.Interval{
			Microseconds: g.nonceTTL.Microseconds(),
			Valid:        true,
		}).Scan(&expiresAt); err != nil {
		g.databaseError(w, r, forwarded{}, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(nonceResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

// nonceBodyLimit bounds the JSON body of the nonce request. The body carries
// one id; anything larger is not a request this service understands.
const nonceBodyLimit = 512

type nonceRequest struct {
	Device string `json:"device"`
}

// readNonceRequest parses the one field and nothing else. A malformed id is a
// 400, which is not an oracle because the id is checked syntactically and never
// looked up.
func readNonceRequest(r *http.Request) ([16]byte, error) {
	var out [16]byte
	if r.Body == nil {
		return out, errors.New("empty body")
	}
	limited := io.LimitReader(r.Body, nonceBodyLimit)
	body, err := io.ReadAll(limited)
	if err != nil {
		return out, err
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var req nonceRequest
	if err := dec.Decode(&req); err != nil {
		return out, err
	}
	// Trailing data after the object is not a request this endpoint accepts.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return out, errors.New("trailing data")
	}
	if trimmed := strings.TrimSpace(req.Device); trimmed == "" || trimmed != req.Device {
		return out, proof.ErrMalformedID
	}
	return proof.ParseDeviceID(req.Device)
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
