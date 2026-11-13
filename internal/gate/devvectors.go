//go:build devtools

package gate

import (
	_ "embed"
	"encoding/json"

	"github.com/chris/aivan-authz/internal/proof"
)

// The shared enrollment vectors, used by the devtools selftest. They live behind
// the tag because nothing in the shipped binary needs them: the reference
// implementation's own test reads the file from disk, the same way.
//
//go:embed enroll_vectors.json
var enrollVectorsJSON []byte

// EnrollVectorsJSON is the vectors as the file holds them, for the browser half
// of the selftest.
func EnrollVectorsJSON() ([]byte, error) { return enrollVectorsJSON, nil }

// EnrollVectors parses the vectors.
func EnrollVectors() ([]EnrollVector, error) {
	var vs []EnrollVector
	if err := json.Unmarshal(enrollVectorsJSON, &vs); err != nil {
		return nil, err
	}
	return vs, nil
}

// EnrollVector is one entry of the shared file.
type EnrollVector struct {
	Name      string `json:"name"`
	Code      string `json:"code"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Expected  string `json:"expected"`
}

// CanonicalForTest runs the Go implementation over one vector, the way the
// browser half runs the JavaScript one.
func CanonicalForTest(code, alg, publicKey string) string {
	return proof.EnrollCanonical(proof.NormalizeEnrollCode(code), alg, publicKey)
}
