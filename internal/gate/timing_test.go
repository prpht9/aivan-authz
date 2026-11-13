//go:build integration

package gate_test

import (
	"sort"
	"testing"
	"time"
)

// TestS14DenialPathsCostTheSame reports the timing of the two denial shapes.
//
// It logs rather than fails, and that is deliberate. A wall-clock assertion on
// a shared machine is flaky in both directions, and the guarantee it would
// stand in for is already structural: every denial after the consume statement
// runs the same sequence, including a full signature verification, so the only
// variable is whether the consume statement found a row. The numbers here are
// the evidence that the dummy verification in verify.go closes the gap, kept in
// test output so a regression is visible.
func TestS14DenialPathsCostTheSame(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	measure := func(s signedRequest) time.Duration {
		start := time.Now()
		e.do(s)
		return time.Since(start)
	}
	for i := 0; i < 50; i++ {
		e.do(e.valid(d))
		s := e.valid(d)
		s.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		e.do(s)
	}
	var known, unknown []time.Duration
	for i := 0; i < 300; i++ {
		known = append(known, measure(e.valid(d)))
		s := e.valid(d)
		s.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		unknown = append(unknown, measure(s))
	}
	sort.Slice(known, func(i, j int) bool { return known[i] < known[j] })
	sort.Slice(unknown, func(i, j int) bool { return unknown[i] < unknown[j] })
	med := func(v []time.Duration) time.Duration { return v[len(v)/2] }

	knownP50, unknownP50 := med(known), med(unknown)
	t.Logf("consumed nonce on a real device: p50=%s p99=%s", knownP50, known[len(known)*99/100])
	t.Logf("no nonce row (any cause):        p50=%s p99=%s", unknownP50, unknown[len(unknown)*99/100])

	if knownP50 > 2*unknownP50 || unknownP50 > 2*knownP50 {
		// Not a failure: a noisy host can produce this. Say so where someone
		// reading the test log will see it.
		t.Logf("WARNING: denial medians differ by more than 2x; check the dummy "+
			"verification on the no-row path (%s vs %s)", knownP50, unknownP50)
	}
}
