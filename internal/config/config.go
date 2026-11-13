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

	TrustedProxies []*net.IPNet

	Policy *Policy
}

// Policy maps a host to the route classes it carries.
type Policy struct {
	Hosts map[string]HostPolicy
}

// HostPolicy is one host's scheme and routes.
type HostPolicy struct {
	Scheme string
	Routes []Route
}

// Route is one path prefix and the class a request under it must satisfy.
type Route struct {
	Prefix string
	Class  string
}

// RouteClass is the set of classes this phase understands. "enrollment" is
// added in Phase F; until then a policy naming it is a startup refusal.
type RouteClass string

const (
	ClassPublic        RouteClass = "public"
	ClassAuthenticated RouteClass = "authenticated"
	ClassAdmin         RouteClass = "admin"
)

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

	if cfg.Policy, err = loadPolicy(cfg.PolicyPath); err != nil {
		return nil, err
	}
	if err := cfg.crossCheck(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) crossCheck() error {
	listed := make(map[string]bool, len(c.Hosts))
	for _, h := range c.Hosts {
		listed[h] = true
	}
	for host, hp := range c.Policy.Hosts {
		if !listed[host] {
			return fmt.Errorf("policy host %q is not listed in AIVAN_HOSTS", host)
		}
		if hp.Scheme != "https" {
			return fmt.Errorf("policy host %q uses scheme %q; only https is allowed", host, hp.Scheme)
		}
		seen := make(map[string]bool, len(hp.Routes))
		for _, r := range hp.Routes {
			if !strings.HasPrefix(r.Prefix, "/") {
				return fmt.Errorf("policy host %q has prefix %q; prefixes start with /", host, r.Prefix)
			}
			if seen[r.Prefix] {
				return fmt.Errorf("policy host %q has prefix %q more than once", host, r.Prefix)
			}
			seen[r.Prefix] = true
		}
	}
	return nil
}

// ParseHosts normalises the comma-separated host list.
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
	Hosts map[string]struct {
		Scheme string `yaml:"scheme"`
		Routes []struct {
			Prefix string `yaml:"prefix"`
			Class  string `yaml:"class"`
		} `yaml:"routes"`
	} `yaml:"hosts"`
}

func loadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return nil, fmt.Errorf("AIVAN_POLICY: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var pf policyFile
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("AIVAN_POLICY %s: %w", path, err)
	}
	if len(pf.Hosts) == 0 {
		return nil, fmt.Errorf("AIVAN_POLICY %s: hosts is empty", path)
	}

	p := &Policy{Hosts: make(map[string]HostPolicy, len(pf.Hosts))}
	for rawHost, hp := range pf.Hosts {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if !validHostname(host) {
			return nil, fmt.Errorf("AIVAN_POLICY %s: host %q is not a bare hostname", path, rawHost)
		}
		scheme := strings.ToLower(hp.Scheme)
		if scheme == "" {
			scheme = "https"
		}
		policy := HostPolicy{Scheme: scheme}
		for _, r := range hp.Routes {
			class := RouteClass(strings.ToLower(r.Class))
			switch class {
			case ClassPublic, ClassAuthenticated, ClassAdmin:
			case "":
				return nil, fmt.Errorf("AIVAN_POLICY %s: host %q has a route with no class", path, host)
			default:
				return nil, fmt.Errorf("AIVAN_POLICY %s: host %q route %q uses unknown class %q", path, host, r.Prefix, r.Class)
			}
			policy.Routes = append(policy.Routes, Route{Prefix: r.Prefix, Class: string(class)})
		}
		p.Hosts[host] = policy
	}
	return p, nil
}
