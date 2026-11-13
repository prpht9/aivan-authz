//go:build devtools

package httpx

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/chris/aivan-authz/internal/gate"
)

// The cross-implementation check.
//
// There is no JavaScript runtime in the shipped image, and there should not be:
// it is a distroless static binary. So the comparison is split in the only way
// that keeps both halves honest:
//
//   - GET /__aivan/selftest        serves a page that loads canonical.js and
//     runs every vector through it in the browser, then shows PASS or FAIL and
//     sets document.title to the result. A browser test drives this.
//   - GET /__aivan/selftest.json   runs the Go implementation against the same
//     vectors and answers 200 or 500. A curl or a Go test reads this.
//
// A drift between web/enroll/canonical.js and internal/proof therefore fails
// one of the two halves. Both are built only with the devtools tag, so the
// shipped image contains neither, and Phase G removes the tag entirely.
func registerDevRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /__aivan/selftest", selftestPage)
	mux.HandleFunc("GET /__aivan/selftest.json", selftestJSON)
	mux.HandleFunc("GET /__aivan/selftest/vectors.json", selftestVectors)
	mux.HandleFunc("GET /__aivan/selftest/canonical.js", selftestCanonical)
}

//go:embed selftest.html
var selftestHTML []byte

func selftestPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(selftestHTML)
}

func selftestCanonical(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(gate.EmbeddedPage().Canonical)
}

func selftestVectors(w http.ResponseWriter, r *http.Request) {
	body, err := gate.EnrollVectorsJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// selftestJSON is the Go half. It answers 500 when its own implementation
// disagrees with the shared vectors, because a reference implementation that
// cannot reproduce its own test data must not report success.
func selftestJSON(w http.ResponseWriter, r *http.Request) {
	type report struct {
		OK       bool     `json:"ok"`
		Vectors  int      `json:"vectors"`
		Failures []string `json:"failures,omitempty"`
	}
	vectors, err := gate.EnrollVectors()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, report{OK: false, Failures: []string{err.Error()}})
		return
	}
	rep := report{OK: true, Vectors: len(vectors)}
	for _, v := range vectors {
		if got := gate.CanonicalForTest(v.Code, v.Alg, v.PublicKey); got != v.Expected {
			rep.OK = false
			rep.Failures = append(rep.Failures, v.Name)
		}
	}
	status := http.StatusOK
	if !rep.OK {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, rep)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
