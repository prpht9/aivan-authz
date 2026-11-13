package gate

import (
	"net/http"
	"strings"

	"github.com/chris/aivan-authz/internal/proof"
)

// forwarded is the request as Traefik saw it. These four values are what the
// client and the gate can agree on: Traefik always sets them and
// authRequestHeaders cannot suppress them, so they are the only ones a device
// can sign.
type forwarded struct {
	Method string
	Scheme string
	Host   string
	Target string
}

const (
	hdrForwardedMethod = "X-Forwarded-Method"
	hdrForwardedProto  = "X-Forwarded-Proto"
	hdrForwardedHost   = "X-Forwarded-Host"
	hdrForwardedURI    = "X-Forwarded-Uri"
)

// forwardedFrom reads the forwarded request context. A missing value is a
// request the gate cannot reproduce, so it is refused rather than guessed: a
// signature must cover the resource the client asked for, and the gate has no
// other source for it.
func forwardedFrom(r *http.Request) (forwarded, bool) {
	f := forwarded{
		Method: strings.ToUpper(strings.TrimSpace(r.Header.Get(hdrForwardedMethod))),
		Scheme: strings.ToLower(strings.TrimSpace(r.Header.Get(hdrForwardedProto))),
		Host:   proof.NormalizeHost(r.Header.Get(hdrForwardedHost)),
		Target: r.Header.Get(hdrForwardedURI),
	}
	if f.Method == "" || f.Scheme == "" || f.Host == "" || f.Target == "" {
		return f, false
	}
	if !strings.HasPrefix(f.Target, "/") {
		return f, false
	}
	return f, true
}

// sourceIP is the address the rate limiter charges. A peer outside the trusted
// proxy ranges cannot set its own X-Forwarded-For, so it is charged as the peer
// it is. Behind the proxies, the rightmost entry is the one the nearest proxy
// appended, which is the client.
func (g *Gate) sourceIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := splitHostPort(peer); err == nil {
		peer = host
	}
	if !g.isTrustedProxy(peer) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}
