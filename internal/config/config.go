// Package config parses the gate's environment and policy file and refuses to
// start on anything the design does not allow.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chris/aivan-authz/internal/policy"
)

const (
	// DefaultPolicyPath is where the installed policy file lives.
	DefaultPolicyPath = "/etc/aivan/policy.yaml"

	// MinMaxBody is the floor for AIVAN_MAX_BODY. Below this the gate cannot
	// forward a request body worth hashing.
	MinMaxBody = 65536
)

// Config is the validated runtime configuration.
type Config struct {
	DBURL      string
	Listen     string
	Hosts      []string
	PolicyPath string

	NonceTTL    time.Duration
	Skew        time.Duration
	SessionIdle time.Duration
	SessionMax  time.Duration
	MaxBody     int64
	// ProxyMaxBody is the ceiling the policy file declares for the proxy in
	// front of the gate, or 0 when it declares none. It must be above MaxBody
	// so the gate answers 413 itself; see the check in Load.
	ProxyMaxBody int64

	TrustedProxies []*net.IPNet

	// Policy is the validated, match-ready route table. It is immutable after
	// Load, so handlers read it without a lock.
	Policy *policy.Table
}

// DatabaseURL reads the one variable `migrate` needs.
func DatabaseURL(getenv func(string) string) (string, error) {
	dsn := strings.TrimSpace(getenv("AIVAN_DB_URL"))
	if dsn == "" {
		return "", errors.New("AIVAN_DB_URL is required")
	}
	return dsn, nil
}

// LoadFromEnv validates the process environment.
func LoadFromEnv() (*Config, error) { return Load(os.Getenv) }

// Load validates configuration read through getenv. Policy file contents are
// read from disk.
func Load(getenv func(string) string) (*Config, error) {
	dsn, err := DatabaseURL(getenv)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		DBURL:      dsn,
		Listen:     value(getenv, "AIVAN_LISTEN", ":8080"),
		PolicyPath: value(getenv, "AIVAN_POLICY", DefaultPolicyPath),
	}

	hosts, err := parseHosts(getenv("AIVAN_HOSTS"))
	if err != nil {
		return nil, err
	}
	cfg.Hosts = hosts

	if cfg.NonceTTL, err = duration(getenv, "AIVAN_NONCE_TTL", "120s"); err != nil {
		return nil, err
	}
	if cfg.Skew, err = duration(getenv, "AIVAN_SKEW", "300s"); err != nil {
		return nil, err
	}
	if cfg.SessionIdle, err = duration(getenv, "AIVAN_SESSION_IDLE", "15m"); err != nil {
		return nil, err
	}
	if cfg.SessionMax, err = duration(getenv, "AIVAN_SESSION_MAX", "8h"); err != nil {
		return nil, err
	}
	if cfg.NonceTTL > cfg.Skew {
		return nil, fmt.Errorf("AIVAN_NONCE_TTL (%s) must not exceed AIVAN_SKEW (%s)", cfg.NonceTTL, cfg.Skew)
	}
	if cfg.SessionIdle >= cfg.SessionMax {
		return nil, fmt.Errorf("AIVAN_SESSION_IDLE (%s) must be less than AIVAN_SESSION_MAX (%s)", cfg.SessionIdle, cfg.SessionMax)
	}

	if cfg.MaxBody, err = int64Value(getenv, "AIVAN_MAX_BODY", 1048576); err != nil {
		return nil, err
	}
	if cfg.MaxBody < MinMaxBody {
		return nil, fmt.Errorf("AIVAN_MAX_BODY (%d) is below the floor of %d bytes", cfg.MaxBody, MinMaxBody)
	}

	if cfg.TrustedProxies, err = parseCIDRs(getenv("AIVAN_TRUSTED_PROXY_CIDRS")); err != nil {
		return nil, err
	}

	if cfg.Policy, cfg.ProxyMaxBody, err = loadPolicy(cfg.PolicyPath); err != nil {
		return nil, err
	}
	if err := cfg.crossCheck(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// crossCheck refuses a policy that names a host the gate does not serve, or a
// body ceiling below the gate's own limit. The route-level checks live in
// policy.New, which the caller runs afterwards.
func (c *Config) crossCheck() error {
	listed := make(map[string]bool, len(c.Hosts))
	for _, h := range c.Hosts {
		listed[h] = true
	}
	for _, host := range c.Policy.Hosts() {
		if !listed[host] {
			return fmt.Errorf("policy host %q is not listed in AIVAN_HOSTS", host)
		}
	}
	// A proxy ceiling at or below the gate's limit means the proxy answers
	// first, with its own status and its own body, for a request the gate would
	// have refused with a 413 naming the limit. The operator then reads a 401
	// from Traefik and learns nothing. The two numbers are in different files,
	// so this refuses the drift rather than trusting it.
	if c.ProxyMaxBody > 0 && c.ProxyMaxBody <= c.MaxBody {
		return fmt.Errorf(
			"policy maxBody (%d) is not above AIVAN_MAX_BODY (%d); the proxy would answer before the gate. "+
				"Set the policy maxBody above AIVAN_MAX_BODY so the gate's 413 is the one a client sees",
			c.ProxyMaxBody, c.MaxBody)
	}
	return nil
}

// ParseHosts normalises the comma-separated host list. It is exported so the
// console commands validate --origin against the same list the gate serves.
func ParseHosts(raw string) ([]string, error) { return parseHosts(raw) }

// parseHosts normalises the comma-separated host list.
func parseHosts(raw string) ([]string, error) {
	var hosts []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h == "" {
			continue
		}
		if strings.Contains(h, "*") {
			return nil, fmt.Errorf("AIVAN_HOSTS entry %q is a wildcard; list hosts explicitly", h)
		}
		if strings.Contains(h, "/") || strings.Contains(h, ":") {
			return nil, fmt.Errorf("AIVAN_HOSTS entry %q must be a bare hostname, without scheme, port or path", h)
		}
		if !validHostname(h) {
			return nil, fmt.Errorf("AIVAN_HOSTS entry %q is not a valid hostname", h)
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("AIVAN_HOSTS is required and must list at least one host")
	}
	return hosts, nil
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("AIVAN_TRUSTED_PROXY_CIDRS entry %q is not a CIDR: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func value(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

func duration(getenv func(string) string, key, def string) (time.Duration, error) {
	raw := value(getenv, key, def)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s (%q) is not a duration: %w", key, raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s (%q) must be positive", key, raw)
	}
	return d, nil
}

func int64Value(getenv func(string) string, key string, def int64) (int64, error) {
	raw := value(getenv, key, strconv.FormatInt(def, 10))
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s (%q) is not a byte count: %w", key, raw, err)
	}
	return v, nil
}

type policyFile struct {
	// MaxBody is the ceiling the proxy in front of this service is configured
	// with, declared in the same file as the routes so the two numbers live
	// next to each other. It is optional: an absent value means the file makes
	// no claim, and only the environment limit applies.
	MaxBody *int64 `yaml:"maxBody"`
	Hosts   map[string]struct {
		Scheme string `yaml:"scheme"`
		Routes []struct {
			Prefix string `yaml:"prefix"`
			Class  string `yaml:"class"`
			// Kinds is the device kinds a `confidential` route accepts. It is
			// empty everywhere else, and policy.New refuses it elsewhere: a
			// `public` or `enrollment` route has no identity whose kind could be
			// checked. KnownFields(true) already makes a typo in the key a
			// refusal, so `kind:` for `kinds:` cannot pass silently.
			Kinds []string `yaml:"kinds"`
		} `yaml:"routes"`
	} `yaml:"hosts"`
}

func loadPolicy(path string) (*policy.Table, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return nil, 0, fmt.Errorf("AIVAN_POLICY: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var pf policyFile
	if err := dec.Decode(&pf); err != nil {
		return nil, 0, fmt.Errorf("AIVAN_POLICY %s: %w", path, err)
	}
	if len(pf.Hosts) == 0 {
		return nil, 0, fmt.Errorf("AIVAN_POLICY %s: hosts is empty", path)
	}

	var proxyMaxBody int64
	if pf.MaxBody != nil {
		if *pf.MaxBody <= 0 {
			return nil, 0, fmt.Errorf("AIVAN_POLICY %s: maxBody (%d) must be positive", path, *pf.MaxBody)
		}
		proxyMaxBody = *pf.MaxBody
	}

	hosts := make(map[string]policy.Host, len(pf.Hosts))
	for rawHost, hp := range pf.Hosts {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if !validHostname(host) {
			return nil, 0, fmt.Errorf("AIVAN_POLICY %s: host %q is not a bare hostname", path, rawHost)
		}
		h := policy.Host{Scheme: strings.ToLower(hp.Scheme)}
		for _, r := range hp.Routes {
			h.Routes = append(h.Routes, policy.Route{
				Prefix: r.Prefix,
				Class:  policy.Class(strings.ToLower(r.Class)),
				Kinds:  r.Kinds,
			})
		}
		hosts[host] = h
	}

	table, err := policy.New(hosts)
	if err != nil {
		// policy.New's messages name the host, prefix and class, but not the
		// file, and an operator needs the file to know where to look.
		return nil, 0, fmt.Errorf("AIVAN_POLICY %s: %w", path, err)
	}
	return table, proxyMaxBody, nil
}
