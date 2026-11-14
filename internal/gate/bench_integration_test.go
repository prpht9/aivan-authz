//go:build integration

package gate_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/chris/aivan-authz/internal/gate"
)

// BenchmarkVerify measures the hot path end to end over HTTP against a local
// database: one nonce issue, one signature, one verify statement.
//
// The nonce is re-issued per iteration because a consumed nonce cannot be
// reused; that is the cost a real client pays. The number the phase's exit
// criterion is about is the verify half, reported separately as sub-benchmarks
// so a regression in the database is not hidden behind the nonce write.
func BenchmarkVerify(b *testing.B) {
	e := newEnv(b)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	b.Run("verify", func(b *testing.B) {
		nonces := make([]signedRequest, b.N)
		for i := range nonces {
			nonces[i] = e.valid(d)
		}
		i := 0
		b.ReportAllocs()
		b.ResetTimer()
		for i < b.N {
			r := e.do(nonces[i])
			if r.Status != 200 {
				b.Fatalf("status = %d %q", r.Status, r.Body)
			}
			i++
		}
	})

	b.Run("nonce", func(b *testing.B) {
		// The limiter is a separate concern with its own test. A benchmark
		// that tripped it would measure the 429 path after three requests.
		srv, client := e.shardedServer(b, 60_000_000, 60_000_000)
		body := `{"device":"` + formatID(d.ID) + `"}`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/__aivan/nonce", strings.NewReader(body))
			if err != nil {
				b.Fatalf("new request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("do: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				b.Fatalf("status = %d", resp.StatusCode)
			}
		}
	})
}

// TestVerifyPercentiles reports p50 and p99 the way C9 asks for them, as a test
// so the number is in `go test` output without a benchmark flag. It is skipped
// under -short because it takes a few thousand round trips.
func TestVerifyPercentiles(t *testing.T) {
	if testing.Short() {
		t.Skip("latency percentiles take a few thousand requests")
	}
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	const samples = 2000
	nonces := make([]signedRequest, samples)
	for i := range nonces {
		nonces[i] = e.valid(d)
	}

	// Warm the pool and the prepared statements with requests that are not
	// part of the sample: a consumed nonce cannot be reused, so warming on the
	// timed slice would make the first fifty samples fail.
	for i := 0; i < 50; i++ {
		if r := e.do(e.valid(d)); r.Status != 200 {
			t.Fatalf("warmup status = %d %q", r.Status, r.Body)
		}
	}

	durations := make([]int64, 0, samples)
	for i := 0; i < samples; i++ {
		start := timeNow()
		r := e.do(nonces[i])
		durations = append(durations, timeSince(start))
		if r.Status != 200 {
			t.Fatalf("sample %d: status = %d %q", i, r.Status, r.Body)
		}
	}
	sortInt64s(durations)

	p50 := durations[len(durations)*50/100]
	p99 := durations[len(durations)*99/100]
	t.Logf("verify latency over %d requests: p50=%s p99=%s max=%s",
		samples, microseconds(p50), microseconds(p99), microseconds(durations[len(durations)-1]))

	if raceDetector {
		// The detector's own overhead is many times the budget, so a number
		// measured here would fail without saying anything about the shipped
		// binary. The report is still printed; see doc/latency-report.md for
		// the figure the budget is asserted against.
		t.Logf("skipping the p99 assertion under -race; the budget applies to the plain build")
		return
	}
	if p99 > 5_000_000 {
		t.Fatalf("p99 = %s, want under 5 ms with the database on localhost", microseconds(p99))
	}

	// The counter is the other half of the budget: a successful verify is one
	// statement, so latency cannot be bought by dropping to zero statements
	// and it cannot regress by adding a second.
	e.counter.Reset()
	if r := e.do(e.valid(d)); r.Status != 200 {
		t.Fatalf("status = %d", r.Status)
	}
	if n := e.counter.Value(); n != 1 {
		t.Fatalf("statements = %d, want 1", n)
	}
}

// TestBenchLine is here so the counter field cannot be quietly removed from the
// test environment: without it, one-statement assertions would compare against
// a zero counter that never moves.
func TestCounterIsWired(t *testing.T) {
	e := newEnv(t)
	e.seedUsers()
	d := e.enroll(userAlice, testHost, "browser", "ed25519")

	e.counter.Reset()
	e.do(e.valid(d)).assertAllowed(t, d)
	if e.counter.Value() != 1 {
		t.Fatalf("counter after one verify = %d, want 1", e.counter.Value())
	}
}

var _ = context.Background
var _ = strconv.Itoa
var _ = gate.ProofNonce
