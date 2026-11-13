package proof

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func ed25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return pub, priv
}

// es256Key returns an uncompressed P-256 public key, which is the wire form a
// browser exports from WebCrypto.
func es256Key(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p-256: %v", err)
	}
	return priv, elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
}

func TestEd25519Verifies(t *testing.T) {
	pub, priv := ed25519Key(t)
	msg := []byte(Canonical(Request{Method: "GET", Scheme: "https", Host: "h.example", Target: "/",
		BodySHA256: EmptyBodySHA256, Nonce: "N1", Timestamp: "1700000000"}))
	sig := ed25519.Sign(priv, msg)

	if err := Verify(string(AlgorithmEd25519), pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A signature over one byte of the message is a different signature.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if err := Verify(string(AlgorithmEd25519), pub, tampered, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered message: err = %v, want ErrInvalidSignature", err)
	}
}

// TestEd25519LengthMismatchIsDenial is the "not a panic" half of C2: a stored
// key or signature of the wrong length denies.
func TestEd25519LengthMismatchIsDenial(t *testing.T) {
	pub, priv := ed25519Key(t)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)

	cases := []struct {
		name     string
		pub, sig []byte
		want     error
	}{
		{"short key", pub[:31], sig, ErrMalformedKey},
		{"long key", append(append([]byte(nil), pub...), 0), sig, ErrMalformedKey},
		{"no key", nil, sig, ErrMalformedKey},
		{"short sig", pub, sig[:63], ErrMalformedSignature},
		{"long sig", pub, append(append([]byte(nil), sig...), 0), ErrMalformedSignature},
		{"no sig", pub, nil, ErrMalformedSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(string(AlgorithmEd25519), tc.pub, msg, tc.sig); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestES256Verifies signs with the same rule WebCrypto applies: SHA-256 over
// the message, then ECDSA. Verify hashes the message itself.
func TestES256Verifies(t *testing.T) {
	priv, pub := es256Key(t)
	msg := []byte("canonical request")
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sha256Bytes(msg))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(string(AlgorithmES256), pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-1] ^= 0x01
	if err := Verify(string(AlgorithmES256), pub, tampered, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered message: err = %v, want ErrInvalidSignature", err)
	}
}

// TestES256AcceptsRawSignature is the Phase F amendment to C8. The wire format
// was designed as DER, and Chromium 158 and Firefox 153 both emit raw r||s from
// subtle.sign (observed 2026-11-13). A gate that refused r||s would refuse
// every browser's ES256 proof, which is the fallback the page relies on when
// Ed25519 is unavailable. Both encodings verify, and the length tells them
// apart: a DER SEQUENCE of two 32-byte integers is never 64 bytes.
func TestES256AcceptsRawSignature(t *testing.T) {
	priv, pub := es256Key(t)
	msg := []byte("canonical request")
	digest := sha256Bytes(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw := make([]byte, P256SignatureRawSize)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])

	if err := Verify(string(AlgorithmES256), pub, msg, raw); err != nil {
		t.Fatalf("raw r||s: err = %v, want nil", err)
	}
	// The raw form is checked against the message, not merely decoded.
	if err := Verify(string(AlgorithmES256), pub, []byte("other"), raw); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("raw r||s over another message: err = %v, want ErrInvalidSignature", err)
	}
	// A 64-byte value that is not a valid pair is malformed, not a panic.
	if err := Verify(string(AlgorithmES256), pub, msg, make([]byte, P256SignatureRawSize)); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("zero r||s: err = %v, want ErrMalformedSignature", err)
	}
}

// TestES256RejectsShortRawSignature: a truncated raw pair is not a DER pair
// either, so it is malformed.
func TestES256RejectsShortRawSignature(t *testing.T) {
	priv, pub := es256Key(t)
	msg := []byte("m")
	digest := sha256Bytes(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw := make([]byte, P256SignatureRawSize)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	if err := Verify(string(AlgorithmES256), pub, msg, raw[:63]); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("truncated raw: err = %v, want ErrMalformedSignature", err)
	}
}

// TestES256RejectsDEROfTheWrongKey proves the signature is checked against the
// key, not just parsed.
func TestES256RejectsDEROfTheWrongKey(t *testing.T) {
	privA, _ := es256Key(t)
	_, pubB := es256Key(t)
	msg := []byte("canonical request")
	sig, err := ecdsa.SignASN1(rand.Reader, privA, sha256Bytes(msg))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(string(AlgorithmES256), pubB, msg, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key: err = %v, want ErrInvalidSignature", err)
	}
}

// TestES256DERWithTrailingGarbage is refused: a signature with bytes after the
// DER pair is not the encoding WebCrypto produces.
func TestES256DERWithTrailingGarbage(t *testing.T) {
	priv, pub := es256Key(t)
	msg := []byte("m")
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sha256Bytes(msg))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(string(AlgorithmES256), pub, msg, append(sig, 0x00)); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("trailing byte: err = %v, want ErrMalformedSignature", err)
	}
}

func TestES256MalformedKey(t *testing.T) {
	_, pub := es256Key(t)
	for _, k := range [][]byte{
		pub[:64], // compressed form is not accepted
		pub[1:],  // off by a byte
		append(append([]byte(nil), pub...), 0),
		make([]byte, 65), // point at infinity encoding is invalid
	} {
		if err := Verify(string(AlgorithmES256), k, []byte("m"), make([]byte, 70)); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("key len %d: err = %v, want ErrMalformedKey", len(k), err)
		}
	}
}

// TestUnsupportedAlgorithms is S17's unit half: anything off the fixed list is
// refused, including case variants of a listed name. The list is keyed off
// devices.alg, so the client never gets a vote.
func TestUnsupportedAlgorithms(t *testing.T) {
	pub, priv := ed25519Key(t)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)

	for _, alg := range []string{"rs256", "none", "ES256", "Ed25519", "ecdsa", "", "es512", "ed448"} {
		t.Run(alg, func(t *testing.T) {
			if Supported(alg) {
				t.Fatalf("Supported(%q) = true", alg)
			}
			if err := Verify(alg, pub, msg, sig); !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("Verify(%q) = %v, want ErrUnsupportedAlgorithm", alg, err)
			}
		})
	}
}

func TestSupportedListedAlgorithms(t *testing.T) {
	for _, alg := range []string{"ed25519", "es256"} {
		if !Supported(alg) {
			t.Fatalf("Supported(%q) = false", alg)
		}
	}
}

// TestAlgorithmConfusionIsRefused: an Ed25519 signature cannot pass as ES256
// and a P-256 key cannot be read as Ed25519.
func TestAlgorithmConfusionIsRefused(t *testing.T) {
	_, edPriv := ed25519Key(t)
	msg := []byte("m")
	edSig := ed25519.Sign(edPriv, msg)
	_, p256 := es256Key(t)

	if err := Verify(string(AlgorithmES256), p256, msg, edSig); err == nil {
		t.Fatal("an Ed25519 signature verified as ES256")
	}
	if err := Verify(string(AlgorithmEd25519), p256, msg, edSig); err == nil {
		t.Fatal("a P-256 key verified as Ed25519")
	}
}

func TestSHA256HexIsLowercase(t *testing.T) {
	got := SHA256Hex([]byte("A"))
	sum := sha256.Sum256([]byte("A"))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256Hex = %q", got)
	}
}

func sha256Bytes(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
