package proof

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnrollCodeRoundTrip proves the mint's display form and the claim's
// normalisation agree: every code the console prints is a code a device can
// type back, with any mixture of case and dashes.
func TestEnrollCodeRoundTrip(t *testing.T) {
	for _, seed := range []string{
		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"00112233445566778899aabbccddeeff",
		"deadbeefdeadbeefdeadbeefdeadbeef",
	} {
		raw, err := hex.DecodeString(seed)
		if err != nil {
			t.Fatalf("decode %q: %v", seed, err)
		}
		display := EncodeEnrollCode(raw)
		normalized := NormalizeEnrollCode(display)
		if !ValidEnrollCode(normalized) {
			t.Fatalf("%s: display form %q normalised to %q, which is not valid",
				seed, display, normalized)
		}
		if len(normalized) != EnrollCodeLen {
			t.Errorf("%s: normalised length = %d, want %d", seed, len(normalized), EnrollCodeLen)
		}
		// Dashes are display only.
		if striped := strings.ReplaceAll(display, "-", ""); striped != normalized {
			t.Errorf("%s: %q without dashes = %q, want %q", seed, display, striped, normalized)
		}
		// Lowercase and extra punctuation are the same code.
		mangled := strings.ToLower(strings.ReplaceAll(display, "-", " "))
		if got := NormalizeEnrollCode(mangled); got != normalized {
			t.Errorf("%s: %q normalised to %q, want %q", seed, mangled, got, normalized)
		}
	}
}

// TestEnrollCodeShape pins the checksum-free reading rules: which characters
// are accepted after normalisation and which are refused.
func TestEnrollCodeShape(t *testing.T) {
	valid := "0123456789ABCDEFGHJKMNPQRS"
	if len(valid) != EnrollCodeLen {
		t.Fatalf("test constant is %d characters, want %d", len(valid), EnrollCodeLen)
	}
	if !ValidEnrollCode(valid) {
		t.Errorf("%q was refused", valid)
	}

	refused := []string{
		"",
		valid[:EnrollCodeLen-1],
		valid + "0",
		"0123456789ABCDEFGHJKMNPQRI",  // I is not in the alphabet
		"0123456789ABCDEFGHJKMNPQRL",  // L is not either
		"0123456789ABCDEFGHJKMNPQRO",  // nor O
		"0123456789ABCDEFGHJKMNPQRU",  // U is excluded
		"0123456789ABCDEFGHJKMNPQR-",  // a separator is never normalised in
		"0123456789ABCDEFGHJKMNPQRS!", // punctuation is dropped, so this is 26
	}
	for _, v := range refused[:len(refused)-1] {
		if ValidEnrollCode(v) {
			t.Errorf("%q was accepted", v)
		}
	}
	// The last case normalises to the valid code, because punctuation is
	// stripped before the length check. That is the documented behaviour and
	// it is why the check runs on the normalised string.
	if got := NormalizeEnrollCode(refused[len(refused)-1]); got != valid {
		t.Errorf("punctuation was not stripped: %q", got)
	}
}

// TestNormalizeEnrollCodeConfusables is the reading rule a human needs: the
// characters Crockford base32 avoids are the ones it maps onto the ones it
// keeps, in both cases.
func TestNormalizeEnrollCodeConfusables(t *testing.T) {
	cases := map[string]string{
		"ilIL":           "1111",
		"oO":             "00",
		"k7qm3xzp":       "K7QM3XZP",
		"K7QM-3XZP":      "K7QM3XZP",
		"\n K7QM 3XZP\n": "K7QM3XZP",
		"k7qm\t3xzp":     "K7QM3XZP",
		"a.b,c":          "ABC",
		"":               "",
	}
	for in, want := range cases {
		if got := NormalizeEnrollCode(in); got != want {
			t.Errorf("NormalizeEnrollCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEnrollCanonicalShape pins the claim's exact bytes. The browser builds the
// same string in web/enroll/canonical.js; testdata/enroll.json is the shared
// set, and this test is the Go half of that check.
func TestEnrollCanonicalShape(t *testing.T) {
	got := EnrollCanonical("K7QM3XZP9WRT4NBHK7QM3XZP9", "es256", "AAECAw")
	want := "aivan-enroll-v1\nK7QM3XZP9WRT4NBHK7QM3XZP9\nes256\nAAECAw"
	if got != want {
		t.Fatalf("EnrollCanonical = %q, want %q", got, want)
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatal("the canonical string has a trailing newline")
	}
	// The enrollment claim must never be mistakable for a device proof.
	if strings.HasPrefix(got, Version+"\n") {
		t.Fatal("the enrollment claim starts with the request version")
	}
}

// TestEnrollCanonicalBindsTheCode pins the property S10 rests on: the signed
// string changes when the code changes, so a signature captured for one record
// cannot verify for another. Without this, the only thing standing between a
// captured claim and a different record would be the digest lookup.
func TestEnrollCanonicalBindsTheCode(t *testing.T) {
	const (
		codeA = "0123456789ABCDEFGHJKMNPQRS"
		codeB = "VDC0H4RWKNZ5Y7TQMAJE6B3NPX"
		key   = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"
	)
	a := EnrollCanonical(codeA, "es256", key)
	b := EnrollCanonical(codeB, "es256", key)
	if a == b {
		t.Fatal("two different codes produced the same signed string")
	}
	if EnrollCanonical(codeA, "ed25519", key) == a {
		t.Fatal("two different algorithms produced the same signed string")
	}
	if EnrollCanonical(codeA, "es256", key+"x") == a {
		t.Fatal("two different keys produced the same signed string")
	}
}

type enrollVector struct {
	Name      string `json:"name"`
	Code      string `json:"code"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	Expected  string `json:"expected"`
}

// loadEnrollVectors reads testdata/enroll.json, the same file the browser's
// selftest reads. A drift between web/enroll/canonical.js and this package
// fails one of the two rather than reaching a user.
func loadEnrollVectors(t *testing.T) []enrollVector {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "enroll.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []enrollVector
	if err := json.Unmarshal(body, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

// TestEnrollVectorsAreOneCopy pins the two files that hold the shared vectors
// to the same bytes.
//
// The authoritative file is testdata/enroll.json, which this package's tests
// read from disk. The devtools selftest embeds a copy in internal/gate, because
// go:embed cannot reach across packages. A copy that drifts would let the
// browser half of the selftest check a different set of vectors than the Go
// half, which is exactly the failure the selftest exists to catch.
func TestEnrollVectorsAreOneCopy(t *testing.T) {
	authoritative, err := os.ReadFile(filepath.Join("testdata", "enroll.json"))
	if err != nil {
		t.Fatalf("read authoritative vectors: %v", err)
	}
	copied, err := os.ReadFile(filepath.Join("..", "gate", "enroll_vectors.json"))
	if err != nil {
		t.Fatalf("read embedded copy: %v", err)
	}
	if string(copied) != string(authoritative) {
		t.Fatal("internal/gate/enroll_vectors.json differs from internal/proof/testdata/enroll.json; " +
			"copy it again so the browser and Go halves of the selftest check the same vectors")
	}
}

func TestEnrollVectors(t *testing.T) {
	for _, v := range loadEnrollVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			code := NormalizeEnrollCode(v.Code)
			if !ValidEnrollCode(code) {
				t.Fatalf("vector code %q normalises to %q, which is not valid", v.Code, code)
			}
			if got := EnrollCanonical(code, v.Alg, v.PublicKey); got != v.Expected {
				t.Fatalf("EnrollCanonical =\n%q\nwant\n%q", got, v.Expected)
			}
		})
	}
}
