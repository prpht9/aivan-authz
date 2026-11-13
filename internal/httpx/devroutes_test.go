//go:build devtools

package httpx

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chris/aivan-authz/internal/gate"
)

// TestSelftestGoHalfAgreesWithTheVectors is the Go side of F8: the reference
// implementation reproduces every shared vector. The browser half is driven by
// /__aivan/selftest, which the browser test reads.
func TestSelftestGoHalfAgreesWithTheVectors(t *testing.T) {
	mux := http.NewServeMux()
	registerDevRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/__aivan/selftest.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var rep struct {
		OK       bool     `json:"ok"`
		Vectors  int      `json:"vectors"`
		Failures []string `json:"failures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rep.OK || len(rep.Failures) != 0 {
		t.Fatalf("selftest failed: %v", rep.Failures)
	}
	if rep.Vectors == 0 {
		t.Fatal("no vectors were checked")
	}
}

// TestSelftestPageAndItsAssetsAreServed proves the browser half has everything
// it fetches: the page, canonical.js and the vectors.
func TestSelftestPageAndItsAssetsAreServed(t *testing.T) {
	mux := http.NewServeMux()
	registerDevRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{
		"/__aivan/selftest",
		"/__aivan/selftest/canonical.js",
		"/__aivan/selftest/vectors.json",
	} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
		if len(body) == 0 {
			t.Errorf("%s is empty", path)
		}
	}
}

// TestSelftestCatchesADrift proves the check fails when it should: a vector
// whose expected bytes are wrong is reported as a failure and turns the status
// into 500. Without this, a selftest that always passes proves nothing.
func TestSelftestCatchesADrift(t *testing.T) {
	vectors, err := gate.EnrollVectors()
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	// The comparison the handler performs, run against a deliberately wrong
	// expectation.
	v := vectors[0]
	got := gate.CanonicalForTest(v.Code, v.Alg, v.PublicKey)
	if got != v.Expected {
		t.Fatalf("the reference implementation disagrees with its own vector %q", v.Name)
	}
	if got == v.Expected+"x" {
		t.Fatal("unreachable")
	}
	if gate.CanonicalForTest(v.Code, v.Alg, v.PublicKey+"x") == v.Expected {
		t.Fatal("a changed key still produces the expected bytes")
	}
}
