// Package policy answers one question per request: what does this path on this
// host require? It is a prefix table, not a rules engine, because the hot path
// can afford a map lookup and a scan and nothing more.
package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Class is what a route requires of a request.
type Class string

const (
	// ClassPublic needs no proof and receives no identity headers.
	ClassPublic Class = "public"
	// ClassAuthenticated needs any active device of an active user.
	ClassAuthenticated Class = "authenticated"
	// ClassAdmin needs the same plus the admin role.
	ClassAdmin Class = "admin"
	// ClassConfidential means "only some device kinds may reach it": it
	// requires a valid device *and* that the device's kind is one the route
	// names, so a route that must not be reachable from a kitchen panel says
	// `kinds: [phone, tablet]` and a browser is refused there.
	//
	// The word is shared with the *level* `confidential` in
	// doc/spec-authorization.md §5.2, which means rank 4 and nothing else. They
	// are different things: a class is a routing requirement, a level is a rank
	// a grant carries. This class is the routing half, and it is the only place
	// in this package the word appears.
	ClassConfidential Class = "confidential"
	// ClassEnrollment is the claim's own class: no user proof, only a body
	// carrying a signed pending-enrollment claim. It is valid on one prefix
	// (EnrollmentPrefix) and nowhere else, because a class that accepts an
	// unauthenticated body is a hole everywhere it is not the point.
	ClassEnrollment Class = "enrollment"
)

// DeviceKinds is the closed vocabulary of device kinds, and the only list of
// them in this service: the schema's CHECK names exactly these
// (aivan-hud/db/migration/202611170100_authz_device_state.rb), the console's
// claimable set and the claim's accepted set are both checked against it by a
// unit test, and a route's `kinds` is validated here.
//
// A fourth copy of the list is how a kind the schema allows and the claim
// refuses becomes a dead end that looks like a typo
// (doc/plan-access-levels.md:277-286).
var DeviceKinds = []string{"phone", "tablet", "browser", "panel", "tv"}

// KnownDeviceKind reports whether k is a kind a device row may have.
func KnownDeviceKind(k string) bool {
	for _, known := range DeviceKinds {
		if k == known {
			return true
		}
	}
	return false
}

// EnrollmentPrefix is the one path an enrollment class may be declared on. It
// matches the gate's own router, which is the only place the claim is served
// (plan §5.7, spec §6.2).
const EnrollmentPrefix = "/__aivan/enroll"

// Known reports whether c is a class this phase understands.
func Known(c Class) bool {
	switch c {
	case ClassPublic, ClassAuthenticated, ClassAdmin, ClassConfidential, ClassEnrollment:
		return true
	default:
		return false
	}
}

// Route is one prefix and the class under it, plus the device kinds the route
// accepts. Kinds is empty for every class but confidential: the others have no
// identity whose kind could be checked, or are meant to accept any device.
type Route struct {
	Prefix string
	Class  Class
	Kinds  []string
}

// Host is one host's routes in match order: longest prefix first, so the first
// match is the answer.
type Host struct {
	// Scheme is always https for a configured host. It is carried here because
	// the canonical string signs it.
	Scheme string
	// Routes is the route list as configured. New sorts and validates a copy,
	// so the caller's slice is not modified.
	Routes []Route
}

// Table is the immutable policy. It is built once at startup and read
// concurrently, so it holds no mutable state.
type Table struct {
	hosts map[string]*builtHost
}

// builtHost is a host whose routes are validated and sorted.
type builtHost struct {
	scheme string
	routes []Route
}

// Match is the outcome of evaluating a request target against one host.
type Match struct {
	Class Class
	Route string // the prefix that matched, or "" when the class defaulted
	// Kinds is the matched route's device-kind list, and is empty whenever the
	// class does not require one. It is empty for a defaulted match too: a path
	// with no policy entry has no kinds to require, and inventing a list there
	// would refuse a device on a route nobody configured.
	Kinds []string
	// Defaulted is true when no prefix matched. The caller logs it, because a
	// path reaching the gate with no policy entry is a routing mistake.
	Defaulted bool
}

var (
	// ErrNoHost means the request host is not in the policy. A host the gate
	// does not know is not a host it may decide for.
	ErrNoHost = errors.New("policy: host is not configured")
	// ErrDuplicatePrefix means one prefix is declared twice on a host. Two
	// classes for one path is ambiguous at startup, so it is refused there.
	ErrDuplicatePrefix = errors.New("policy: prefix declared more than once")
	// ErrBadPrefix means a prefix does not start with /.
	ErrBadPrefix = errors.New("policy: prefix must start with /")
	// ErrUnknownClass means a class this phase does not implement.
	ErrUnknownClass = errors.New("policy: unknown class")
	// ErrEnrollmentPrefix means an enrollment route was declared somewhere
	// other than EnrollmentPrefix. The class exists for one endpoint; a
	// second use of it would be a second unauthenticated write path.
	ErrEnrollmentPrefix = errors.New("policy: enrollment class is only valid on " + EnrollmentPrefix)
	// ErrScheme means a host is configured with a scheme other than https.
	ErrScheme = errors.New("policy: scheme must be https")
	// ErrUnknownKind means a route names a device kind outside DeviceKinds. A
	// typo there would otherwise make a route that quietly accepts nothing.
	ErrUnknownKind = errors.New("policy: unknown device kind")
	// ErrKindsOnClass means `kinds` was put where it cannot be enforced: on
	// `public` or `enrollment` (neither has an identity to check), or on
	// `confidential` with an empty list (which would be `authenticated` under a
	// second name).
	ErrKindsOnClass = errors.New("policy: kinds is not allowed on this class")
)

// refusal carries an operator-facing message while still matching its
// sentinel with errors.Is, so a caller can branch on the kind of refusal
// without parsing prose.
type refusal struct {
	sentinel error
	msg      string
}

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return r.sentinel }

func failf(sentinel error, format string, args ...any) error {
	return &refusal{sentinel: sentinel, msg: fmt.Sprintf(format, args...)}
}

// New builds a table from a host map. Routes within a host are sorted longest
// prefix first, which makes matching a single linear scan with the documented
// precedence. Equal-length duplicates are refused: the order would be
// arbitrary, and an arbitrary order for an authorization decision is a bug
// waiting for a quiet deployment.
func New(hosts map[string]Host) (*Table, error) {
	t := &Table{hosts: make(map[string]*builtHost, len(hosts))}
	for rawHost, h := range hosts {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if host == "" {
			return nil, errors.New("policy: empty host name")
		}
		if h.Scheme == "" {
			h.Scheme = "https"
		}
		if h.Scheme != "https" {
			return nil, failf(ErrScheme, "policy host %q uses scheme %q; only https is allowed", host, h.Scheme)
		}

		routes := make([]Route, 0, len(h.Routes))
		seen := make(map[string]bool, len(h.Routes))
		for _, r := range h.Routes {
			if !strings.HasPrefix(r.Prefix, "/") {
				return nil, failf(ErrBadPrefix, "policy host %q has prefix %q; prefixes start with /", host, r.Prefix)
			}
			if !Known(r.Class) {
				if r.Class == "" {
					return nil, failf(ErrUnknownClass, "policy host %q has a route with no class (prefix %q)", host, r.Prefix)
				}
				return nil, failf(ErrUnknownClass, "policy host %q route %q uses unknown class %q", host, r.Prefix, r.Class)
			}
			if seen[r.Prefix] {
				return nil, failf(ErrDuplicatePrefix, "policy host %q has prefix %q more than once", host, r.Prefix)
			}
			// The enrollment class accepts a body with no user proof, so it is
			// pinned to the one endpoint that needs it (spec §6.2, plan §5.7).
			if r.Class == ClassEnrollment && r.Prefix != EnrollmentPrefix {
				return nil, failf(ErrEnrollmentPrefix,
					"policy host %q declares class %q on %q, which is not %s",
					host, r.Class, r.Prefix, EnrollmentPrefix)
			}
			kinds, err := normaliseKinds(host, r)
			if err != nil {
				return nil, err
			}
			r.Kinds = kinds
			seen[r.Prefix] = true
			routes = append(routes, r)
		}
		// Longest first. A stable tie-break is unnecessary because equal
		// prefixes are refused above.
		sortRoutes(routes)

		t.hosts[host] = &builtHost{scheme: h.Scheme, routes: routes}
	}
	return t, nil
}

// normaliseKinds validates one route's `kinds` against its class, and returns
// the list to keep. The rules are the startup refusals the plan names
// (doc/plan-gate-device-kinds.md step 3), each with its own sentinel:
//
//   - a value outside DeviceKinds is ErrUnknownKind, so a typo stops the gate
//     rather than producing a route that accepts nothing;
//   - `kinds` on `public` or `enrollment` is ErrKindsOnClass: neither has an
//     identity whose kind could be checked, so the field would be an
//     expectation nothing enforces;
//   - `confidential` with an empty list is ErrKindsOnClass: it would be
//     `authenticated` under a second name.
//
// Any other class keeps an empty list, and a route that names kinds there is
// refused rather than silently ignored.
func normaliseKinds(host string, r Route) ([]string, error) {
	seen := make(map[string]bool, len(r.Kinds))
	kinds := make([]string, 0, len(r.Kinds))
	for _, raw := range r.Kinds {
		k := strings.ToLower(strings.TrimSpace(raw))
		if !KnownDeviceKind(k) {
			return nil, failf(ErrUnknownKind,
				"policy host %q route %q names device kind %q; the kinds are %s",
				host, r.Prefix, raw, strings.Join(DeviceKinds, ", "))
		}
		if seen[k] {
			return nil, failf(ErrUnknownKind, "policy host %q route %q names device kind %q twice",
				host, r.Prefix, k)
		}
		seen[k] = true
		kinds = append(kinds, k)
	}

	switch r.Class {
	case ClassConfidential:
		if len(kinds) == 0 {
			return nil, failf(ErrKindsOnClass,
				"policy host %q route %q is class %q with no kinds; "+
					"a confidential route with no kinds is an authenticated route under another name",
				host, r.Prefix, r.Class)
		}
	case ClassPublic, ClassEnrollment:
		if len(kinds) != 0 {
			return nil, failf(ErrKindsOnClass,
				"policy host %q route %q is class %q, which has no device identity to check; "+
					"kinds belongs on %q",
				host, r.Prefix, r.Class, ClassConfidential)
		}
	default:
		if len(kinds) != 0 {
			return nil, failf(ErrKindsOnClass,
				"policy host %q route %q is class %q and names kinds; "+
					"only %q requires them",
				host, r.Prefix, r.Class, ClassConfidential)
		}
	}
	return kinds, nil
}

// Hosts returns the configured host names.
func (t *Table) Hosts() []string {
	out := make([]string, 0, len(t.hosts))
	for h := range t.hosts {
		out = append(out, h)
	}
	return out
}

// Scheme reports the scheme for host, and whether it is configured.
func (t *Table) Scheme(host string) (string, bool) {
	h, ok := t.hosts[strings.ToLower(host)]
	if !ok {
		return "", false
	}
	return h.scheme, true
}

// Match evaluates target (path plus query, as X-Forwarded-Uri carries it)
// against host.
//
// A target that matches no prefix is class authenticated with Defaulted set.
// That is deliberate: serving an uncovered path as public is a silent open
// door, while requiring a proof is a visible 401 an operator fixes by editing
// the policy.
func (t *Table) Match(host, target string) (Match, error) {
	h, ok := t.hosts[strings.ToLower(host)]
	if !ok {
		return Match{}, ErrNoHost
	}
	path := target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		path = "/"
	}

	for _, r := range h.routes {
		if r.Prefix == "/" || path == r.Prefix || strings.HasPrefix(path, r.Prefix+"/") {
			return Match{Class: r.Class, Route: r.Prefix, Kinds: r.Kinds}, nil
		}
	}
	return Match{Class: ClassAuthenticated, Defaulted: true}, nil
}

// sortRoutes orders longest prefix first by insertion sort. The slice is tiny
// and built once, so an import of sort would be ceremony.
func sortRoutes(routes []Route) {
	for i := 1; i < len(routes); i++ {
		for j := i; j > 0 && len(routes[j].Prefix) > len(routes[j-1].Prefix); j-- {
			routes[j], routes[j-1] = routes[j-1], routes[j]
		}
	}
}
