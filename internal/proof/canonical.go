// Package proof owns the device-proof wire format: the canonical request
// string and the signature algorithms. It is the only place in Go that knows
// either, so testdata/canonical.json is the single definition the browser
// implementation is tested against too.
package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Version is the first line of every canonical string. A future format change
// bumps it, which makes an old client's signature invalid rather than
// ambiguous.
const Version = "aivan-v1"

// Request is everything a device signs. The zero value is not meaningful: Max
// fills it from the forwarded headers.
type Request struct {
	Method     string
	Scheme     string
	Host       string
	Target     string
	BodySHA256 string
	Nonce      string
	Timestamp  string
}

// Canonical returns the exact bytes a device signs, in the fixed field order.
//
// The builder is preallocated because this runs on every verify; fmt.Sprintf
// would be both slower and a place for a format verb to drift.
func Canonical(r Request) string {
	var b strings.Builder
	b.Grow(256)
	b.WriteString(Version)
	b.WriteByte('\n')
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(r.Scheme)
	b.WriteString("://")
	b.WriteString(r.Host)
	b.WriteByte('\n')
	b.WriteString(r.Target)
	b.WriteByte('\n')
	b.WriteString(r.BodySHA256)
	b.WriteByte('\n')
	b.WriteString(r.Nonce)
	b.WriteByte('\n')
	b.WriteString(r.Timestamp)
	return b.String()
}

// EmptyBodySHA256 is the digest of zero bytes, used for methods whose body is
// not hashed.
var EmptyBodySHA256 = SHA256Hex(nil)

// SHA256Hex is the lowercase hex digest of body.
func SHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SHA256Sum is the raw digest, for storage. Nonces are stored hashed so a
// database read does not yield a usable one.
func SHA256Sum(body []byte) [32]byte { return sha256.Sum256(body) }

// NormalizeHost lowercases a forwarded host and strips a port. The browser
// strips the port from location.host the same way, so both sides sign the same
// value.
func NormalizeHost(host string) string {
	h := strings.TrimSpace(host)

	// Bracketed IPv6 literal: [::1]:8080 -> [::1].
	if end := strings.LastIndexByte(h, ']'); end >= 0 {
		h = h[:end+1]
	} else if i := strings.IndexByte(h, ':'); i >= 0 && strings.LastIndexByte(h, ':') == i &&
		allDigits(h[i+1:]) {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// Path returns the path part of a request target, without the query. Policy is
// matched on the path; the signature covers the whole target.
func Path(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i]
	}
	return target
}

// ParseDeviceID accepts the canonical UUID form only: 36 characters, lowercase
// hex and four dashes. One id has one spelling, so a device cannot present two
// strings that resolve to the same row.
func ParseDeviceID(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 36 {
		return out, ErrMalformedID
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return out, ErrMalformedID
			}
			continue
		}
		v, ok := hexNibble(s[i])
		if !ok {
			return out, ErrMalformedID
		}
		out[n/2] <<= 4
		out[n/2] |= v
		n++
	}
	return out, nil
}

// FormatDeviceID renders a device id in the canonical form ParseDeviceID
// accepts.
func FormatDeviceID(id [16]byte) string {
	const hexdigits = "0123456789abcdef"
	var b [36]byte
	n := 0
	for i, c := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b[n] = '-'
			n++
		}
		b[n] = hexdigits[c>>4]
		b[n+1] = hexdigits[c&0x0f]
		n += 2
	}
	return string(b[:])
}

// ParseTimestamp accepts the decimal unix-seconds form. Negative values and
// non-digits are refused rather than parsed loosely.
func ParseTimestamp(s string) (int64, error) {
	if s == "" || len(s) > 19 {
		return 0, ErrMalformedTimestamp
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrMalformedTimestamp
		}
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, ErrMalformedTimestamp
	}
	return ts, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var (
	// ErrMalformedID reports a device id that is not in canonical form.
	ErrMalformedID = errors.New("proof: malformed device id")
	// ErrMalformedTimestamp reports a timestamp that is not decimal seconds.
	ErrMalformedTimestamp = errors.New("proof: malformed timestamp")
)
