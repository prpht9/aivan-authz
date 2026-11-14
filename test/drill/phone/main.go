// Command phone claims an enrollment code from a terminal the way a native app
// claims one, then makes a gated request with the cookie it was given.
//
// It exists because aivan-hud/doc/plan-web-and-mobile-registration.md step 5
// asks for the phone's wire to be proved before any Swift or Kotlin exists, and
// a test in the gate's package proves it against a scratch database, not against
// the install. This is the same four calls against a real host:
//
//	POST /__aivan/enroll   the code, the kind, a generated Ed25519 key, a signature
//	GET  <path>            start a session, holding only the cookie
//	DELETE /__aivan/session end it
//	GET  <path>            refused, because the session is gone
//
// The private key is generated in memory, used for the claim, and never written
// anywhere. There is nothing to reuse: a real phone keeps its key in the secure
// enclave, and the point of the claim is that the key stays there.
//
// Usage:
//
//	phone -target https://aivan-hud.home.arpa -code ABCD-EFGH-... [-kind phone] [-path /admin]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/chris/aivan-authz/internal/proof"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "phone:", err)
		os.Exit(1)
	}
}

type claimResponse struct {
	DeviceID string `json:"device_id"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

func run() error {
	var (
		target   = flag.String("target", "https://aivan-hud.home.arpa", "the host the code was minted for")
		code     = flag.String("code", "", "the enrollment code the operator printed")
		kind     = flag.String("kind", "phone", "device kind: phone, tablet or browser")
		path     = flag.String("path", "/admin", "gated path to request after enrolling")
		insecure = flag.Bool("insecure", false, "skip TLS verification (the house CA is self-signed)")
	)
	flag.Parse()

	if strings.TrimSpace(*code) == "" {
		return fmt.Errorf("missing -code; mint one with `authz-admin enroll-new`")
	}
	switch *kind {
	case "phone", "tablet", "browser":
	default:
		return fmt.Errorf("-kind %q is not phone, tablet or browser", *kind)
	}

	base, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("-target: %w", err)
	}
	if base.Scheme != "https" {
		return fmt.Errorf("-target must be https: the session cookie is __Host- and needs a secure origin")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar}
	if *insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- an operator watches the LAN this runs on
	}

	// The key stays here: generated now, used for one signature, then garbage.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	wireKey := base64.RawURLEncoding.EncodeToString(pub)
	normalised := proof.NormalizeEnrollCode(*code)
	message := proof.EnrollCanonical(normalised, "ed25519", wireKey)

	body, err := json.Marshal(map[string]string{
		"code":       normalised,
		"kind":       *kind,
		"alg":        "ed25519",
		"public_key": wireKey,
		"signature":  base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(message))),
	})
	if err != nil {
		return err
	}

	enrollURL := base.JoinPath("/__aivan/enroll")
	req, err := http.NewRequest(http.MethodPost, enrollURL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		// The gate's denial is deliberately constant, so the status is the
		// whole message. Print it and stop.
		return fmt.Errorf("claim refused: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var claimed claimResponse
	if err := json.Unmarshal(raw, &claimed); err != nil {
		return fmt.Errorf("decode claim: %w", err)
	}
	fmt.Printf("enrolled %s as %s (user %d, device %s)\n",
		*kind, claimed.Username, claimed.UserID, claimed.DeviceID)
	fmt.Printf("cookie: %d stored by the jar\n", len(jar.Cookies(base)))

	status, err := gatedGet(client, base.JoinPath(*path))
	if err != nil {
		return err
	}
	fmt.Printf("GET %s with the session: %d\n", *path, status)

	// End the session the way the page's sign-out control does. A native client
	// sends the CSRF header on every non-GET under a cookie session.
	if err := endSession(client, base); err != nil {
		return err
	}
	fmt.Println("session ended")

	status, err = gatedGet(client, base.JoinPath(*path))
	if err != nil {
		return err
	}
	fmt.Printf("GET %s after sign-out: %d\n", *path, status)
	if status < 400 {
		return fmt.Errorf("the session still works after sign-out")
	}
	return nil
}

// gatedGet follows the path as a client would. The cookie jar attaches the
// session; a gated route answers 200 for an admin and a 401 or 302 otherwise.
func gatedGet(client *http.Client, u *url.URL) (int, error) {
	// A redirect from the gate means "not authenticated"; report it rather than
	// following it to the enrollment page, which is what a browser would show.
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := clone.Get(u.String())
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", u.Path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// endSession deletes the gate's session. The CSRF token is a presence test, so
// any well-formed value passes; a real client generates one per request.
func endSession(client *http.Client, base *url.URL) error {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, base.JoinPath("/__aivan/session").String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Aivan-Csrf", base64.RawURLEncoding.EncodeToString(token))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("end session: %d", resp.StatusCode)
	}
	return nil
}
