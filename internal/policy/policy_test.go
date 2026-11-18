package policy

import (
	"errors"
	"strings"
	"testing"
)

func table(t *testing.T) *Table {
	t.Helper()
	tbl, err := New(map[string]Host{
		"hud.example": {
			Routes: []Route{
				{Prefix: "/", Class: ClassAuthenticated},
				{Prefix: "/admin", Class: ClassAdmin},
				{Prefix: "/admin/audit", Class: ClassAdmin},
				{Prefix: "/public", Class: ClassPublic},
				{Prefix: "/api/v1", Class: ClassPublic},
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tbl
}

// TestLongestPrefixWins is C8's policy item, first half: /admin/audit beats
// /admin beats /, regardless of declaration order.
func TestLongestPrefixWins(t *testing.T) {
	tbl := table(t)
	cases := []struct {
		target string
		class  Class
		route  string
	}{
		{"/", ClassAuthenticated, "/"},
		{"/index", ClassAuthenticated, "/"},
		{"/admin", ClassAdmin, "/admin"},
		{"/admin/users", ClassAdmin, "/admin"},
		{"/admin/audit", ClassAdmin, "/admin/audit"},
		{"/admin/audit/log?x=1", ClassAdmin, "/admin/audit"},
		{"/administrator", ClassAuthenticated, "/"},
		{"/public/thing", ClassPublic, "/public"},
		{"/api/v1/x", ClassPublic, "/api/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			m, err := tbl.Match("hud.example", tc.target)
			if err != nil {
				t.Fatalf("Match: %v", err)
			}
			if m.Class != tc.class || m.Route != tc.route {
				t.Fatalf("Match(%q) = %s via %q, want %s via %q", tc.target, m.Class, m.Route, tc.class, tc.route)
			}
			if m.Defaulted {
				t.Fatalf("Match(%q) defaulted despite a matching prefix", tc.target)
			}
		})
	}
}

// TestPrefixMatchesWholeSegments: "/api" must not match "/apifoo", because a
// prefix is a path prefix and not a string prefix. Otherwise a route declared
// for /api would silently govern an unrelated neighbour.
func TestPrefixMatchesWholeSegments(t *testing.T) {
	tbl, err := New(map[string]Host{
		"hud.example": {Routes: []Route{{Prefix: "/api", Class: ClassPublic}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, target := range []string{"/apifoo", "/apifoo/x"} {
		m, _ := tbl.Match("hud.example", target)
		if !m.Defaulted {
			t.Errorf("%q matched prefix %q", target, m.Route)
		}
	}
	for _, target := range []string{"/api", "/api/", "/api/x"} {
		m, _ := tbl.Match("hud.example", target)
		if m.Route != "/api" {
			t.Errorf("%q matched %q, want /api", target, m.Route)
		}
	}
}

// TestEqualLengthPrefixIsRefused is C8's second policy item. Two routes for one
// path make the decision arbitrary, so the table will not build.
func TestEqualLengthPrefixIsRefused(t *testing.T) {
	_, err := New(map[string]Host{
		"hud.example": {Routes: []Route{
			{Prefix: "/admin", Class: ClassAdmin},
			{Prefix: "/admin", Class: ClassAuthenticated},
		}},
	})
	if !errors.Is(err, ErrDuplicatePrefix) {
		t.Fatalf("err = %v, want ErrDuplicatePrefix", err)
	}
}

// TestUncoveredPathDefaultsToAuthenticated is C8's third policy item. A path
// with no prefix is not public.
func TestUncoveredPathDefaultsToAuthenticated(t *testing.T) {
	tbl, err := New(map[string]Host{
		"hud.example": {Routes: []Route{{Prefix: "/public", Class: ClassPublic}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m, err := tbl.Match("hud.example", "/anything")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if m.Class != ClassAuthenticated {
		t.Fatalf("class = %s, want authenticated", m.Class)
	}
	if !m.Defaulted {
		t.Fatal("Defaulted is false; the caller could not log reason=class_defaulted")
	}
	if m.Route != "" {
		t.Fatalf("Route = %q, want empty for a defaulted match", m.Route)
	}
}

// TestAdminRequiresTheRole is the matching half of S7: an admin prefix resolves
// to the admin class, which is what makes the role check happen at all.
func TestAdminRequiresTheRole(t *testing.T) {
	tbl := table(t)
	m, err := tbl.Match("hud.example", "/admin")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if m.Class != ClassAdmin {
		t.Fatalf("class = %s, want admin", m.Class)
	}
}

func TestUnknownHostIsRefused(t *testing.T) {
	tbl := table(t)
	if _, err := tbl.Match("other.example", "/"); !errors.Is(err, ErrNoHost) {
		t.Fatalf("err = %v, want ErrNoHost", err)
	}
	if _, err := tbl.Match("HUD.EXAMPLE", "/"); err != nil {
		t.Fatalf("a case-variant host should match: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name string
		host Host
		want error
	}{
		{"unknown class", Host{Routes: []Route{{Prefix: "/", Class: Class("operator")}}}, ErrUnknownClass},
		{"empty class", Host{Routes: []Route{{Prefix: "/", Class: Class("")}}}, ErrUnknownClass},
		{"enrollment off its prefix", Host{Routes: []Route{{Prefix: "/", Class: ClassEnrollment}}}, ErrEnrollmentPrefix},
		{"prefix without slash", Host{Routes: []Route{{Prefix: "admin", Class: ClassAdmin}}}, ErrBadPrefix},
		{"non-https scheme", Host{Scheme: "http", Routes: []Route{{Prefix: "/", Class: ClassAdmin}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(map[string]Host{"hud.example": tc.host})
			if tc.name == "non-https scheme" {
				if err == nil {
					t.Fatal("http scheme accepted")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestScheme(t *testing.T) {
	tbl := table(t)
	if s, ok := tbl.Scheme("hud.example"); !ok || s != "https" {
		t.Fatalf("Scheme = %q, %v", s, ok)
	}
	if _, ok := tbl.Scheme("nope.example"); ok {
		t.Fatal("Scheme reported a host that is not configured")
	}
}

// TestKindsAreValidatedAtStartup is the pair of refusals step 3 adds. Each has
// its own sentinel so the message and errors.Is agree: a typo in a kind stops
// the gate rather than making a route that quietly accepts nothing, and `kinds`
// where it cannot be enforced stops it rather than looking restrictive.
func TestKindsAreValidatedAtStartup(t *testing.T) {
	cases := []struct {
		name string
		host Host
		want error
	}{
		{"a confidential route with kinds", Host{Routes: []Route{
			{Prefix: "/", Class: ClassConfidential, Kinds: []string{"phone"}}}}, nil},
		{"a kind outside the vocabulary", Host{Routes: []Route{
			{Prefix: "/", Class: ClassConfidential, Kinds: []string{"panelx"}}}}, ErrUnknownKind},
		{"a confidential route with no kinds", Host{Routes: []Route{
			{Prefix: "/", Class: ClassConfidential}}}, ErrKindsOnClass},
		{"kinds on public", Host{Routes: []Route{
			{Prefix: "/", Class: ClassPublic, Kinds: []string{"phone"}}}}, ErrKindsOnClass},
		{"kinds on enrollment", Host{Routes: []Route{
			{Prefix: EnrollmentPrefix, Class: ClassEnrollment, Kinds: []string{"phone"}}}}, ErrKindsOnClass},
		{"kinds on authenticated", Host{Routes: []Route{
			{Prefix: "/", Class: ClassAuthenticated, Kinds: []string{"phone"}}}}, ErrKindsOnClass},
		{"kinds on admin", Host{Routes: []Route{
			{Prefix: "/admin", Class: ClassAdmin, Kinds: []string{"phone"}}}}, ErrKindsOnClass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(map[string]Host{"hud.example": tc.host})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestMatchCarriesTheRoutesKinds: the kinds reach the decision through Match, so
// a caller cannot see the class and miss the kinds.
func TestMatchCarriesTheRoutesKinds(t *testing.T) {
	tbl, err := New(map[string]Host{
		"hud.example": {
			Routes: []Route{
				{Prefix: "/", Class: ClassAuthenticated},
				{Prefix: "/vault", Class: ClassConfidential, Kinds: []string{"phone", "tablet"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	m, err := tbl.Match("hud.example", "/vault/notes")
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if m.Class != ClassConfidential {
		t.Fatalf("class = %s, want confidential", m.Class)
	}
	if got := strings.Join(m.Kinds, ","); got != "phone,tablet" {
		t.Fatalf("kinds = %q, want phone,tablet", got)
	}

	// The defaulted match and an ordinary route carry none, so no device is
	// refused on a route that never asked for one.
	for _, target := range []string{"/", "/elsewhere"} {
		m, err = tbl.Match("hud.example", target)
		if err != nil {
			t.Fatalf("Match(%q): %v", target, err)
		}
		if len(m.Kinds) != 0 {
			t.Errorf("Match(%q) carried kinds %v on a route that names none", target, m.Kinds)
		}
	}
}

// TestDeviceKindsAreTheSchemaVocabulary pins the list the migration's CHECK
// names. A fourth copy of the vocabulary is how a kind the schema allows and the
// claim refuses becomes a dead end.
func TestDeviceKindsAreTheSchemaVocabulary(t *testing.T) {
	want := "phone,tablet,browser,panel,tv"
	if got := strings.Join(DeviceKinds, ","); got != want {
		t.Fatalf("DeviceKinds = %q, want %q", got, want)
	}
	for _, k := range DeviceKinds {
		if !KnownDeviceKind(k) {
			t.Errorf("KnownDeviceKind(%q) = false", k)
		}
	}
	for _, k := range []string{"", "watch", "fridge", "Phone"} {
		if KnownDeviceKind(k) {
			t.Errorf("KnownDeviceKind(%q) = true", k)
		}
	}
}
