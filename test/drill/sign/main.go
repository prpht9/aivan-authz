// Command sign sends one signed request to a running gate, the way a browser
// would, and prints the status and body.
//
// It exists for the failure drills in doc/runbook.md: replaying a captured
// request, sending one with a skewed timestamp, and watching a revoke take
// effect are all "send this request and tell me the status", and doing that
// with curl means re-deriving the canonical string by hand each time.
//
// It holds no key of its own. The device and its private key come from files
// the enrollment page produced, or from the load seeder. There is no mode that
// mints a device: this is a request sender, not an enrollment.
//
// Usage:
//
//	sign -target https://aivan-hud.home.arpa -device <uuid> -key key.jwk [-skew 10m] [-repeat 2]
//
// -key is a JWK file (the private half). -skew moves the timestamp a request
// claims, so a 10-minute skew is `-skew 10m`.
//
// The host in -target is what the canonical string signs, so the request goes
// to the gated host, not to /__aivan/verify.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		target    = flag.String("target", "https://aivan-hud.home.arpa", "gated origin to send to")
		path      = flag.String("path", "/dashboard", "application path to request")
		method    = flag.String("method", "GET", "request method")
		device    = flag.String("device", "", "device id (uuid)")
		keyFile   = flag.String("key", "", "JWK file holding the device's private key")
		body      = flag.String("body", "", "request body; its digest is signed")
		bodyFile  = flag.String("body-file", "", "read the request body from this file (for bodies too large for an argument)")
		skew      = flag.Duration("skew", 0, "how far the request's timestamp is from now")
		repeat    = flag.Int("repeat", 1, "send the request this many times, reusing the nonce")
		nonce     = flag.String("nonce", "", "use this nonce instead of one at random (the nonce must exist in the database)")
		nonceFile = flag.String("nonce-file", "", "use the next nonce from this JSON pool file; each run takes the first unused one")
		cookie    = flag.String("cookie", "", "send this session cookie instead of a proof, which is the cookie half of the decision")
		cookieOut = flag.String("cookie-out", "", "write the Set-Cookie value from a mint to this file")
		insecure  = flag.Bool("insecure", false, "skip TLS verification (the home.arpa certificate is self-signed)")
	)
	flag.Parse()

	if *device == "" || *keyFile == "" {
		return fmt.Errorf("-device and -key are required")
	}
	u, err := url.Parse(*target)
	if err != nil || u.Host == "" {
		return fmt.Errorf("-target %q is not a URL", *target)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("-target %q is not https; the gate signs the scheme", *target)
	}
	key, err := loadJWK(*keyFile)
	if err != nil {
		return err
	}

	payload := []byte(*body)
	if *bodyFile != "" {
		raw, err := os.ReadFile(*bodyFile) // #nosec G304 -- the caller names the file
		if err != nil {
			return err
		}
		payload = raw
	}

	// The canonical string signs the bare host, the way the gate normalises
	// X-Forwarded-Host. Signing the dialled address with its port would be a
	// different message.
	host := u.Hostname()

	timestamp := time.Now().Add(*skew).Unix()
	bodyDigest := sha256Hex(payload)
	target_path := *path
	if !strings.HasPrefix(target_path, "/") {
		target_path = "/" + target_path
	}

	// A cookie request carries no proof at all, so nothing is signed and no
	// nonce is spent. That is the session half of the decision.
	var proof nonceProof
	switch {
	case *cookie != "":
	case *nonce != "":
		proof, err = signWith(*device, key, *method, host, target_path, bodyDigest, *nonce, timestamp)
	case *nonceFile != "":
		var nonce string
		if nonce, err = takeNonce(*nonceFile); err != nil {
			return err
		}
		proof, err = signWith(*device, key, *method, host, target_path, bodyDigest, nonce, timestamp)
	default:
		proof, err = signNew(*device, key, *method, host, target_path, bodyDigest, timestamp, u, *insecure)
	}
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}, // #nosec G402 -- the flag is explicit and documented
		},
		// A redirect is a denial shape the drill reports, not something to
		// follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	for i := 1; i <= *repeat; i++ {
		var bodyReader io.Reader
		if len(payload) > 0 {
			bodyReader = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(*method, *target+target_path, bodyReader)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if *cookie != "" {
			// A cookie request carries no proof: the session path is the one
			// a browser takes after a mint, and it is what a revoke must break.
			req.Header.Set("Cookie", "__Host-aivan_session="+*cookie)
			if *method != http.MethodGet && *method != http.MethodHead {
				req.Header.Set("X-Aivan-Csrf", "drill-csrf-token-0123456789")
			}
		} else {
			req.Header.Set("X-Aivan-Device", proof.device)
			req.Header.Set("X-Aivan-Nonce", proof.nonce)
			req.Header.Set("X-Aivan-Signature", proof.signature)
			req.Header.Set("X-Aivan-Timestamp", proof.timestamp)
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if *cookieOut != "" {
			for _, c := range resp.Cookies() {
				if c.Name == "__Host-aivan_session" {
					if err := os.WriteFile(*cookieOut, []byte(c.Value), 0o600); err != nil {
						return err
					}
				}
			}
		}
		fmt.Printf("attempt %d: %d %s body=%q request_id=%s\n", i, resp.StatusCode,
			http.StatusText(resp.StatusCode), truncate(string(raw), 120), resp.Header.Get("X-Aivan-Request-Id"))
	}
	return nil
}

type nonceProof struct {
	device    string
	nonce     string
	signature string
	timestamp string
}

// takeNonce consumes the next unused nonce from a pool file and rewrites the
// file with the rest. A pool is what test/load/seed writes, and a single-use
// nonce cannot be reused across drill runs, so the file is the cursor.
func takeNonce(path string) (string, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- the caller names the file
	if err != nil {
		return "", err
	}
	var pool []string
	if err := json.Unmarshal(body, &pool); err != nil {
		return "", fmt.Errorf("%s is not a nonce pool: %w", path, err)
	}
	if len(pool) == 0 {
		return "", fmt.Errorf("%s has no nonces left", path)
	}
	rest, err := json.Marshal(pool[1:])
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, rest, 0o600); err != nil {
		return "", err
	}
	return pool[0], nil
}

// signWith signs one canonical request with an explicit nonce.
func signWith(device string, key *ecdsa.PrivateKey, method, host, path, bodyDigest, nonce string, ts int64) (nonceProof, error) {
	stamp := fmt.Sprintf("%d", ts)
	message := canonical(method, "https", host, path, bodyDigest, nonce, stamp)
	sig, err := sign(key, []byte(message))
	if err != nil {
		return nonceProof{}, err
	}
	return nonceProof{device: device, nonce: nonce, signature: sig, timestamp: stamp}, nil
}

// signNew asks the gate for a nonce and signs a request with it.
func signNew(device string, key *ecdsa.PrivateKey, method, host, path, bodyDigest string, ts int64, u *url.URL, insecure bool) (nonceProof, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, // #nosec G402 -- explicit flag
		},
	}
	body := fmt.Sprintf(`{"device":%q}`, device)
	resp, err := client.Post(u.Scheme+"://"+u.Host+"/__aivan/nonce", "application/json", strings.NewReader(body))
	if err != nil {
		return nonceProof{}, fmt.Errorf("nonce: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nonceProof{}, fmt.Errorf("nonce: %d %q", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nonceProof{}, err
	}
	return signWith(device, key, method, host, path, bodyDigest, out.Nonce, ts)
}

// canonical is internal/proof.Canonical, restated here because this is a
// standalone tool that must not import the gate's packages.
func canonical(method, scheme, host, target, bodyDigest, nonce, timestamp string) string {
	return strings.Join([]string{"aivan-v1", method, scheme + "://" + host, target,
		bodyDigest, nonce, timestamp}, "\n")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sign produces the raw r||s the gate accepts for ES256.
func sign(key *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	raw := bytes.Join([][]byte{pad(r), pad(s)}, nil)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pad(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// loadJWK reads a P-256 private JWK.
func loadJWK(path string) (*ecdsa.PrivateKey, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- the caller names the file
	if err != nil {
		return nil, err
	}
	var j struct{ Kty, Crv, X, Y, D string }
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, fmt.Errorf("%s is not a JWK: %w", path, err)
	}
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("%s is %s/%s, want EC/P-256", path, j.Kty, j.Crv)
	}
	field := func(name, v string) (*big.Int, error) {
		raw, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return new(big.Int).SetBytes(raw), nil
	}
	x, err := field("x", j.X)
	if err != nil {
		return nil, err
	}
	y, err := field("y", j.Y)
	if err != nil {
		return nil, err
	}
	d, err := field("d", j.D)
	if err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	if priv.PublicKey.Curve.Params().N == nil || !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("%s: the public point is not on P-256", path)
	}
	return priv, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
