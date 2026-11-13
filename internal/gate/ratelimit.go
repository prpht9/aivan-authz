package gate

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Rate limits for the nonce endpoint. A client needs one nonce per request it
// signs, so the limit is generous enough for a busy page and tight enough that
// one address cannot fill the table.
const (
	NonceRatePerMinute = 30
	NonceBurst         = 10
)

// rateLimiter is a token bucket per key. It is deliberately small: a map of
// buckets, a sweep, and a mutex that is held for the arithmetic only.
type rateLimiter struct {
	perSecond float64
	burst     float64

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

func newRateLimiter(perMinute, burst int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		perSecond: float64(perMinute) / 60,
		burst:     float64(burst),
		buckets:   make(map[string]*bucket),
		lastSweep: now(),
		now:       now,
	}
}

// Allow charges one token to key and reports whether one was available.
func (l *rateLimiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// A bucket idle for longer than this can refill from empty, so forgetting
	// it changes no decision.
	if now.Sub(l.lastSweep) >= time.Minute {
		l.sweep(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.perSecond
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.last = now
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled and gone quiet. Without it the map
// grows with every address that ever called, which is a slow leak an attacker
// controls.
func (l *rateLimiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > time.Minute {
			delete(l.buckets, k)
		}
	}
	l.lastSweep = now
}

// isTrustedProxy reports whether ip falls inside one of the configured proxy
// CIDRs.
func (g *Gate) isTrustedProxy(ip string) bool {
	if len(g.TrustedProxies) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.TrustedProxies {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// decisionLogger is the one place a decision is written. It carries the fields
// spec §8.3 asks for and nothing that could be a secret: no nonce, no
// signature, no cookie, no key.
type decisionLogger struct{ log *slog.Logger }

type decision struct {
	RequestID string
	Host      string
	Method    string
	Route     string
	UserID    int64
	DeviceID  string
	Allow     bool
	Reason    Reason
	Status    int
}

func (d decisionLogger) write(r *http.Request, dec decision) {
	subject := "anonymous"
	if dec.UserID != 0 {
		subject = itoa(dec.UserID)
	}
	verdict := "deny"
	if dec.Allow {
		verdict = "allow"
	}
	d.log.Info("decision",
		"request_id", dec.RequestID,
		"host", dec.Host,
		"method", dec.Method,
		"route", dec.Route,
		"user_id", subject,
		"device_id", dec.DeviceID,
		"decision", verdict,
		"reason", string(dec.Reason),
		"status", dec.Status,
	)
}

func splitHostPort(hostport string) (host, port string, err error) {
	return net.SplitHostPort(hostport)
}
