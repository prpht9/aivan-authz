package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chris/aivan-authz/internal/policy"
)

const goodPolicy = `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin, class: admin }
      - { prefix: /,      class: authenticated }
`

// pinnedEnrollment is the policy the deployment runs once enrollment exists:
// the claim's class on its one prefix, and the ordinary classes under it.
const pinnedEnrollmentPolicy = `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /__aivan/enroll, class: enrollment }
      - { prefix: /admin,          class: admin }
      - { prefix: /,               class: authenticated }
`

// writePolicy writes a policy file into a temp dir and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// env builds a getenv for a complete, valid environment.
func env(t *testing.T, overrides map[string]string) func(string) string {
	t.Helper()
	base := map[string]string{
		"AIVAN_DB_URL":       "postgres://aivan_authz@localhost/aivan_authz",
		"AIVAN_HOSTS":        "aivan-hud.home.arpa",
		"AIVAN_POLICY":       writePolicy(t, goodPolicy),
		"AIVAN_NONCE_TTL":    "120s",
		"AIVAN_SKEW":         "300s",
		"AIVAN_SESSION_IDLE": "15m",
		"AIVAN_SESSION_MAX":  "8h",
		"AIVAN_MAX_BODY":     "1048576",
	}
	for k, v := range overrides {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(t, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", cfg.Listen)
	}
	if cfg.NonceTTL != 120*time.Second || cfg.Skew != 300*time.Second {
		t.Errorf("TTLs = %s/%s, want 120s/300s", cfg.NonceTTL, cfg.Skew)
	}
	if cfg.SessionIdle != 15*time.Minute || cfg.SessionMax != 8*time.Hour {
		t.Errorf("sessions = %s/%s, want 15m/8h", cfg.SessionIdle, cfg.SessionMax)
	}
	if cfg.MaxBody != 1048576 {
		t.Errorf("MaxBody = %d, want 1048576", cfg.MaxBody)
	}
	hp, ok := cfg.Policy.Scheme("aivan-hud.home.arpa")
	if !ok {
		t.Fatalf("policy host missing: %v", cfg.Policy.Hosts())
	}
	if hp != "https" {
		t.Errorf("scheme = %q, want https", hp)
	}
	m, err := cfg.Policy.Match("aivan-hud.home.arpa", "/admin/users")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if m.Class != policy.ClassAdmin || m.Route != "/admin" {
		t.Fatalf("Match(/admin/users) = %s via %q, want admin via /admin", m.Class, m.Route)
	}
}

// TestRefusals is the B2 matrix: every refusal the plan names has a case, and
// each case fails if its guard in config.go is removed.
func TestRefusals(t *testing.T) {
	unknownClass := writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /enroll, class: operator }
`)
	enrollmentClass := writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /enroll, class: enrollment }
`)
	notListed := writePolicy(t, `
hosts:
  other.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)
	httpScheme := writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    scheme: http
    routes:
      - { prefix: /, class: authenticated }
`)
	badYAML := writePolicy(t, "hosts: [")
	emptyHosts := writePolicy(t, "hosts: {}\n")
	noLeadingSlash := writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: admin, class: admin }
`)
	duplicatePrefix := writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin, class: admin }
      - { prefix: /admin, class: authenticated }
`)

	cases := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{
			name:    "db url empty",
			env:     map[string]string{"AIVAN_DB_URL": ""},
			wantSub: "AIVAN_DB_URL is required",
		},
		{
			name:    "hosts empty",
			env:     map[string]string{"AIVAN_HOSTS": ""},
			wantSub: "AIVAN_HOSTS is required",
		},
		{
			name:    "hosts wildcard",
			env:     map[string]string{"AIVAN_HOSTS": "*.home.arpa"},
			wantSub: "wildcard",
		},
		{
			name:    "hosts with scheme",
			env:     map[string]string{"AIVAN_HOSTS": "https://aivan-hud.home.arpa"},
			wantSub: "bare hostname",
		},
		{
			name:    "policy host not in hosts",
			env:     map[string]string{"AIVAN_POLICY": notListed},
			wantSub: "not listed in AIVAN_HOSTS",
		},
		{
			name:    "policy scheme not https",
			env:     map[string]string{"AIVAN_POLICY": httpScheme},
			wantSub: "only https is allowed",
		},
		{
			name:    "unknown class",
			env:     map[string]string{"AIVAN_POLICY": unknownClass},
			wantSub: `unknown class "operator"`,
		},
		{
			name:    "enrollment class on the wrong prefix",
			env:     map[string]string{"AIVAN_POLICY": enrollmentClass},
			wantSub: `declares class "enrollment" on "/enroll", which is not /__aivan/enroll`,
		},
		{
			name: "route with no class",
			env: map[string]string{"AIVAN_POLICY": writePolicy(t, `
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin }
`)},
			wantSub: "no class",
		},
		{
			name:    "policy unparseable",
			env:     map[string]string{"AIVAN_POLICY": badYAML},
			wantSub: "AIVAN_POLICY",
		},
		{
			name:    "policy hosts empty",
			env:     map[string]string{"AIVAN_POLICY": emptyHosts},
			wantSub: "hosts is empty",
		},
		{
			name:    "policy file missing",
			env:     map[string]string{"AIVAN_POLICY": "/nonexistent/policy.yaml"},
			wantSub: "AIVAN_POLICY",
		},
		{
			name:    "prefix without slash",
			env:     map[string]string{"AIVAN_POLICY": noLeadingSlash},
			wantSub: "prefixes start with /",
		},
		{
			name:    "duplicate prefix",
			env:     map[string]string{"AIVAN_POLICY": duplicatePrefix},
			wantSub: "more than once",
		},
		{
			name:    "nonce ttl exceeds skew",
			env:     map[string]string{"AIVAN_NONCE_TTL": "600s", "AIVAN_SKEW": "300s"},
			wantSub: "must not exceed AIVAN_SKEW",
		},
		{
			name:    "session idle equals max",
			env:     map[string]string{"AIVAN_SESSION_IDLE": "8h", "AIVAN_SESSION_MAX": "8h"},
			wantSub: "must be less than AIVAN_SESSION_MAX",
		},
		{
			name:    "session idle exceeds max",
			env:     map[string]string{"AIVAN_SESSION_IDLE": "9h", "AIVAN_SESSION_MAX": "8h"},
			wantSub: "must be less than AIVAN_SESSION_MAX",
		},
		{
			name:    "max body below floor",
			env:     map[string]string{"AIVAN_MAX_BODY": "65535"},
			wantSub: "below the floor",
		},
		{
			name:    "max body not a number",
			env:     map[string]string{"AIVAN_MAX_BODY": "1MB"},
			wantSub: "not a byte count",
		},
		{
			name:    "duration unparseable",
			env:     map[string]string{"AIVAN_SKEW": "five minutes"},
			wantSub: "not a duration",
		},
		{
			name:    "negative duration",
			env:     map[string]string{"AIVAN_SKEW": "-300s"},
			wantSub: "must be positive",
		},
		{
			name:    "trusted proxy not a cidr",
			env:     map[string]string{"AIVAN_TRUSTED_PROXY_CIDRS": "10.0.0.0/33"},
			wantSub: "not a CIDR",
		},
		{
			name: "policy maxBody below the gate limit",
			env: map[string]string{"AIVAN_POLICY": writePolicy(t, `
maxBody: 524288
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)},
			wantSub: "is not above AIVAN_MAX_BODY",
		},
		{
			name: "policy maxBody equal to the gate limit",
			env: map[string]string{"AIVAN_POLICY": writePolicy(t, `
maxBody: 1048576
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)},
			wantSub: "is not above AIVAN_MAX_BODY",
		},
		{
			name: "policy maxBody not a number",
			env: map[string]string{"AIVAN_POLICY": writePolicy(t, `
maxBody: 2MB
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)},
			wantSub: "AIVAN_POLICY",
		},
		{
			name: "policy maxBody zero",
			env: map[string]string{"AIVAN_POLICY": writePolicy(t, `
maxBody: 0
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)},
			wantSub: "must be positive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(env(t, tc.env))
			if err == nil {
				t.Fatalf("Load succeeded, want refusal containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestBoundariesAccepted(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"nonce ttl equal to skew", map[string]string{"AIVAN_NONCE_TTL": "300s", "AIVAN_SKEW": "300s"}},
		{"max body at floor", map[string]string{"AIVAN_MAX_BODY": "65536"}},
		{"trusted proxies", map[string]string{"AIVAN_TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 192.168.0.0/16"}},
		{"multi host", map[string]string{
			"AIVAN_HOSTS":  "aivan-hud.home.arpa, AIVAN-HUD.home.arpa, second.home.arpa",
			"AIVAN_POLICY": writePolicy(t, goodPolicy),
		}},
		{"enrollment class on its own prefix", map[string]string{
			"AIVAN_POLICY": writePolicy(t, pinnedEnrollmentPolicy),
		}},
		{"proxy ceiling above the gate limit", map[string]string{"AIVAN_POLICY": writePolicy(t, `
maxBody: 2097152
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /, class: authenticated }
`)}},
		{"no proxy ceiling declared", map[string]string{"AIVAN_POLICY": writePolicy(t, goodPolicy)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(env(t, tc.env)); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
	}
}

func TestHostsAreNormalisedAndDeduplicated(t *testing.T) {
	cfg, err := Load(env(t, map[string]string{
		"AIVAN_HOSTS": " AIVAN-HUD.home.arpa ,aivan-hud.home.arpa,second.home.arpa ",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"aivan-hud.home.arpa", "second.home.arpa"}
	if strings.Join(cfg.Hosts, ",") != strings.Join(want, ",") {
		t.Fatalf("Hosts = %v, want %v", cfg.Hosts, want)
	}
}

func TestDatabaseURL(t *testing.T) {
	if _, err := DatabaseURL(func(string) string { return "" }); err == nil {
		t.Fatal("empty AIVAN_DB_URL accepted")
	}
	got, err := DatabaseURL(func(k string) string { return " postgres://x " })
	if err != nil || got != "postgres://x" {
		t.Fatalf("DatabaseURL = %q, %v", got, err)
	}
}
