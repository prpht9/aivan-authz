package console

import (
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/policy"
)

// TestClaimableKindsAreSchemaKinds: the console's list and the schema's
// vocabulary are two different questions — what a mint may produce, what a row
// may be — but they must not disagree in either direction. A kind here that
// policy.DeviceKinds does not name is a mint that produces a row the column
// CHECK refuses at claim time; a device kind missing here is a kind the schema
// admits and nobody can produce, which is a dead end that reads as a typo
// (doc/plan-access-levels.md:277-286).
//
// The set comparison is what makes the real guard: TestEnrollMintsEveryClaimableKind
// loops over this list, so a narrowed list would leave that loop passing
// vacuously. This test is what notices the list shrank.
func TestClaimableKindsAreSchemaKinds(t *testing.T) {
	for _, kind := range ClaimableKinds {
		if !policy.KnownDeviceKind(kind) {
			t.Errorf("ClaimableKinds has %q, which is not a policy.DeviceKind (%v)",
				kind, policy.DeviceKinds)
		}
	}
	if len(ClaimableKinds) == 0 {
		t.Fatal("ClaimableKinds is empty")
	}

	claimable := make(map[string]bool, len(ClaimableKinds))
	for _, kind := range ClaimableKinds {
		claimable[kind] = true
	}
	for _, kind := range policy.DeviceKinds {
		if !claimable[kind] {
			t.Errorf("policy.DeviceKinds has %q but a mint cannot produce one", kind)
		}
	}
	if len(ClaimableKinds) != len(policy.DeviceKinds) {
		t.Fatalf("ClaimableKinds has %d entries, policy.DeviceKinds has %d",
			len(ClaimableKinds), len(policy.DeviceKinds))
	}

	// The plan's step 1 acceptance: a panel and a tv can be minted, and a kind
	// outside the five is refused with a message naming all five.
	for _, kind := range []string{"panel", "tv"} {
		var got string
		if err := normaliseKind(kind, &got); err != nil {
			t.Errorf("normaliseKind(%q): %v", kind, err)
		}
		if got != kind {
			t.Errorf("normaliseKind(%q) = %q", kind, got)
		}
	}

	var out string
	err := normaliseKind("fridge", &out)
	if err == nil {
		t.Fatal("fridge was accepted")
	}
	for _, kind := range policy.DeviceKinds {
		if !strings.Contains(err.Error(), kind) {
			t.Errorf("the refusal does not name %q: %v", kind, err)
		}
	}
}
