// Package relay is the operator tool's client for aivan-approval: the mailbox
// that addresses a request to a phone and verifies what the phone signs.
//
// It speaks the two routes a home service may call, and nothing else:
//
//	POST   /devices        register a phone's public key, signed with the
//	                       service key this tool holds
//	DELETE /devices/{id}   retire it, signed the same way
//
// The service key is the credential. aivan-approval resolves X-Aivan-Service to
// a live row and verifies X-Aivan-Signature over the exact bytes sent, so a
// caller that holds the private half can register a device key against any user
// id it names. That is why the key lives on a workstation and never in the
// cluster, and why the package is imported by cmd/authz-admin alone.
//
// Nothing here builds a canonical string. The signature covers the request body
// as sent, which is the relay's own rule (`Relay::Auth`): a second builder would
// be a second opinion about bytes the relay verifies.
package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chris/aivan-authz/internal/proof"
	"github.com/chris/aivan-authz/internal/servicekey"
)

const (
	// DefaultURL is the proof-of-concept host. It is a default so a first run
	// needs no environment, not a promise that the host will not move.
	DefaultURL = "https://approval-dev.cincyaivan.com"

	// DevicesPath is the one route this package writes.
	DevicesPath = "/devices"

	// The relay caps a buffered body at 8192 bytes (Relay::BodyBuffer). A
	// registration is a few hundred bytes, so a body near that limit means
	// something is wrong and the refusal is better than the round trip.
	maxBody = 8192

	// timeout bounds one call. The relay answers a registration from one
	// transaction; a host that does not answer in this window is reported, not
	// retried, because the enrollment that produced the device has already
	// succeeded.
	timeout = 15 * time.Second
)

// DeviceKinds are the kinds aivan-approval accepts (Relay::Devices::KINDS). A
// panel or a television has no place in the relay's registry: it cannot sign a
// device proof, so a row for one would be a row nothing can use.
var DeviceKinds = []string{"phone", "tablet", "browser"}

// DeviceAlgs are the algorithms aivan-approval accepts for a *device's* key
// (Relay::Devices::ALGORITHMS).
//
// This is not the service key's algorithm. The two keys are independent: this
// tool signs the registration with its own Ed25519 service key, and the body
// carries the phone's public key, which the phone generated in its Keystore. An
// Android Keystore produces P-256 and nothing else, so a phone always registers
// es256 — and a check that compared the two would refuse every phone.
var DeviceAlgs = []string{"ed25519", "es256"}

// Registration is one POST /devices body.
//
// UserID is a string because the relay stores it as text: the home's id is
// opaque to the relay and may not stay a bigint.
type Registration struct {
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Alg       string `json:"alg"`
	Kind      string `json:"kind"`
}

// Device is what the relay says it stored.
type Device struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Alg    string `json:"alg"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
}

// Client is a relay endpoint and the key that authenticates it.
type Client struct {
	base  *url.URL
	key   *servicekey.KeyPair
	http  *http.Client
	name  string
	clock func() time.Time
}

// Options configure a Client.
type Options struct {
	// URL is the relay's base URL, for example https://approval-dev.cincyaivan.com.
	URL string
	// Key is the service key the relay has registered under Name.
	Key *servicekey.KeyPair
	// CAFile is an optional PEM bundle to trust in place of the system roots.
	// The house CA is self-signed, so a workstation that has not installed it
	// uses this rather than turning verification off.
	CAFile string
	// HTTP overrides the transport, for a test against a local server.
	HTTP *http.Client
}

// New validates the endpoint and builds the client.
func New(o Options) (*Client, error) {
	if o.Key == nil {
		return nil, errors.New("relay: no service key")
	}
	raw := strings.TrimSpace(o.URL)
	if raw == "" {
		raw = DefaultURL
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("relay url %q: %w", raw, err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, fmt.Errorf("relay url %q must be https", raw)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("relay url %q names no host", raw)
	}

	client := o.HTTP
	if client == nil {
		transport, err := transport(o.CAFile)
		if err != nil {
			return nil, err
		}
		client = &http.Client{Timeout: timeout, Transport: transport}
	}

	return &Client{base: base, key: o.Key, http: client, name: o.Key.Name, clock: time.Now}, nil
}

// transport builds the one transport a registration uses. A CA file adds to the
// roots rather than replacing them, so a public host and the house CA both work
// from one workstation.
func transport(caFile string) (*http.Transport, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caFile) != "" {
		body, err := os.ReadFile(caFile) // #nosec G304 -- the operator names the path
		if err != nil {
			return nil, fmt.Errorf("read relay CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(body) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}, nil
}

// URL is the endpoint a caller names in an operator message.
func (c *Client) URL() string { return c.base.String() }

// Register adds or refreshes a device row. A 200 means the relay already held
// the id and updated it; a 201 means it created one. Both are success, because a
// retry after a lost response must be safe.
func (c *Client) Register(ctx context.Context, reg Registration) (Device, error) {
	var out Device
	if err := validate(reg); err != nil {
		return out, err
	}

	body, err := json.Marshal(reg)
	if err != nil {
		return out, fmt.Errorf("encode registration: %w", err)
	}
	if len(body) > maxBody {
		return out, fmt.Errorf("registration is %d bytes, above the relay's %d-byte limit", len(body), maxBody)
	}

	resp, err := c.do(ctx, http.MethodPost, DevicesPath, body)
	if err != nil {
		return out, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
			return out, fmt.Errorf("relay answered %d with a body this tool could not read: %w", resp.StatusCode, err)
		}
		return out, nil
	case http.StatusConflict:
		return out, errors.New("the relay has this device id revoked; a revoked id stays dead there. " +
			"Re-enroll the phone so it gets a new device id")
	case http.StatusUnauthorized:
		return out, fmt.Errorf("the relay refused the service signature: it has no live service named %q "+
			"with this key. Register the public key there with `rake \"service:register[%s]\" KEY=%s`",
			c.name, c.name, c.key.Name+".pub")
	case http.StatusUnprocessableEntity:
		return out, fmt.Errorf("the relay refused the registration's fields (%s)", readError(resp))
	case http.StatusTooManyRequests:
		return out, errors.New("the relay is rate limiting this service; wait and run it again")
	default:
		return out, fmt.Errorf("the relay answered %d (%s)", resp.StatusCode, readError(resp))
	}
}

// Retire marks a device revoked at the relay. A 404 is reported as such: the id
// is not one the relay holds, which is worth knowing rather than ignoring.
func (c *Client) Retire(ctx context.Context, deviceID string) error {
	if strings.TrimSpace(deviceID) == "" {
		return errors.New("relay: empty device id")
	}
	path := DevicesPath + "/" + url.PathEscape(deviceID)

	// The relay signs the body it receives, so a DELETE signs the empty body.
	resp, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("the relay has no device %s", deviceID)
	case http.StatusUnauthorized:
		return fmt.Errorf("the relay refused the service signature: it has no live service named %q "+
			"with this key", c.name)
	default:
		return fmt.Errorf("the relay answered %d (%s)", resp.StatusCode, readError(resp))
	}
}

// do sends one signed request. The signature is base64 (standard, padded), which
// is the form the relay's decode64 reads and the form `openssl` writes.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Aivan-Service", c.name)
	req.Header.Set("X-Aivan-Signature", base64.StdEncoding.EncodeToString(c.key.Sign(body)))

	resp, err := c.http.Do(req)
	if err != nil {
		// A transport failure names the host and nothing else: a wrapped error
		// from the TLS stack can quote the URL, and the URL carries no secret
		// but the message is not worth the risk of a future one.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, fmt.Errorf("relay %s did not answer: %v", c.base.Host, urlErr.Err)
		}
		return nil, fmt.Errorf("relay %s did not answer", c.base.Host)
	}
	return resp, nil
}

// validate checks a registration before it is signed, so a typo is a local
// refusal rather than a 422 from a host across the internet.
func validate(reg Registration) error {
	if strings.TrimSpace(reg.UserID) == "" {
		return errors.New("registration names no user id")
	}
	if strings.TrimSpace(reg.DeviceID) == "" {
		return errors.New("registration names no device id")
	}
	if strings.TrimSpace(reg.PublicKey) == "" {
		return errors.New("registration carries no public key")
	}
	// The payload is the device's key, and its algorithm is the device's. Check
	// the spelling against the relay's list, then decode and check the length,
	// so a mistyped algorithm or a truncated key is refused here rather than as
	// a 422 from a host across the internet.
	if !contains(DeviceAlgs, reg.Alg) {
		return fmt.Errorf("the relay accepts device algorithms %s, not %q",
			strings.Join(DeviceAlgs, ", "), reg.Alg)
	}
	key, err := decodeKey(reg.PublicKey)
	if err != nil {
		return err
	}
	if err := proof.ValidatePublicKey(reg.Alg, key); err != nil {
		return fmt.Errorf("the public key is not a %s key: %w", reg.Alg, err)
	}
	for _, kind := range DeviceKinds {
		if reg.Kind == kind {
			return nil
		}
	}
	return fmt.Errorf("the relay registers kinds %s, not %q",
		strings.Join(DeviceKinds, ", "), reg.Kind)
}

// decodeKey accepts the base64 spellings an operator's tool produces. The relay
// decodes both padded standard and unpadded URL base64 (Relay::Signature), so a
// key copied from either form is a key this can check.
func decodeKey(text string) ([]byte, error) {
	value := strings.TrimSpace(text)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(value); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("the public key is not base64")
}

// contains reports membership in a short list.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// readError returns the relay's `{"error": "..."}` value, or a constant when the
// body is not that shape. A body is never echoed whole: it is a remote host's
// text and it belongs in a log line, not a terminal that is being read for a
// decision.
func readError(resp *http.Response) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&payload); err == nil && payload.Error != "" {
		return payload.Error
	}
	return "no detail"
}

// drain reads a little and closes, so a keep-alive connection can be reused
// without buffering a body nobody reads.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}
