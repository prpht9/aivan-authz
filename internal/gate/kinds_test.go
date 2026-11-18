package gate

import (
	"testing"

	"github.com/chris/aivan-authz/internal/policy"
)

// TestEnrollKindsAreSchemaKinds: the claim accepts exactly the schema's
// vocabulary. It is derived from policy.DeviceKinds so it cannot lag the CHECK,
// and this test is what makes that derivation a requirement rather than a
// detail of the current code.
func TestEnrollKindsAreSchemaKinds(t *testing.T) {
	for _, kind := range policy.DeviceKinds {
		if !enrollKinds[kind] {
			t.Errorf("a claim cannot name %q, which the column allows", kind)
		}
	}
	if len(enrollKinds) != len(policy.DeviceKinds) {
		t.Fatalf("enrollKinds has %d entries, policy.DeviceKinds has %d",
			len(enrollKinds), len(policy.DeviceKinds))
	}
	for _, kind := range []string{"watch", "fridge", "Phone", ""} {
		if enrollKinds[kind] {
			t.Errorf("a claim can name %q", kind)
		}
	}
}

// TestOccupantlessKindsAreTheScreens pins the stand-in that makes a panel
// anonymous at the device. When `authz.devices.shared` lands this set goes away
// and the test goes with it, so the two facts cannot drift apart quietly.
func TestOccupantlessKindsAreTheScreens(t *testing.T) {
	for _, kind := range []string{"panel", "tv"} {
		if !occupantlessKinds[kind] {
			t.Errorf("%q should carry no occupant", kind)
		}
		if hasOccupant(kind) {
			t.Errorf("hasOccupant(%q) = true", kind)
		}
	}
	for _, kind := range []string{"phone", "tablet", "browser"} {
		if occupantlessKinds[kind] {
			t.Errorf("%q should carry its owner", kind)
		}
		if !hasOccupant(kind) {
			t.Errorf("hasOccupant(%q) = false", kind)
		}
	}
	// Every occupantless kind is one the schema allows, so the set cannot name
	// a device that does not exist.
	for kind := range occupantlessKinds {
		if !policy.KnownDeviceKind(kind) {
			t.Errorf("occupantlessKinds names %q, which is not a device kind", kind)
		}
	}
}
