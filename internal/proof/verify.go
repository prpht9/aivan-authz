package proof

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

// Algorithm is one entry of the fixed list. The list is keyed off
// devices.alg and never off a request field (S17): a client cannot choose an
// algorithm per request.
type Algorithm string

const (
	AlgorithmEd25519 Algorithm = "ed25519"
	AlgorithmES256   Algorithm = "es256"
)

// Wire-format sizes. Ed25519 public keys and signatures are fixed length; an
// ES256 public key is one uncompressed P-256 point.
const (
	Ed25519PublicKeySize = ed25519.PublicKeySize
	Ed25519SignatureSize = ed25519.SignatureSize
	P256PublicKeySize    = 65
	// P256SignatureRawSize is r||s with each integer left-padded to 32 bytes,
	// which is the form WebCrypto emits on the browsers Phase F tested.
	P256SignatureRawSize = 64
)

var (
	// ErrUnsupportedAlgorithm means devices.alg is not on the fixed list.
	ErrUnsupportedAlgorithm = errors.New("proof: algorithm not in the fixed list")
	// ErrMalformedKey means the stored public key cannot be a key of its
	// algorithm. A length mismatch is a denial, never a panic.
	ErrMalformedKey = errors.New("proof: public key is not valid for its algorithm")
	// ErrMalformedSignature means the signature is not the wire format its
	// algorithm requires, for example a raw r||s ES256 signature.
	ErrMalformedSignature = errors.New("proof: signature is not valid for its algorithm")
	// ErrInvalidSignature means the signature is well formed and wrong.
	ErrInvalidSignature = errors.New("proof: signature does not verify")
)

// Supported reports whether alg is on the fixed list.
func Supported(alg string) bool {
	switch Algorithm(alg) {
	case AlgorithmEd25519, AlgorithmES256:
		return true
	default:
		return false
	}
}

// ValidatePublicKey reports whether key is a public key of alg's wire size. It
// is the shape check an enrollment claim runs before any database work: a key
// of the wrong length is a malformed request, which is a different answer from
// a claim that does not match a record.
func ValidatePublicKey(alg string, key []byte) error {
	switch Algorithm(alg) {
	case AlgorithmEd25519:
		if len(key) != Ed25519PublicKeySize {
			return ErrMalformedKey
		}
	case AlgorithmES256:
		// An uncompressed P-256 point, which is what exportKey('raw') emits
		// and what ParseUncompressedPublicKey accepts. The point must also be
		// on the curve: a 65-byte string is not automatically a key.
		if len(key) != P256PublicKeySize {
			return ErrMalformedKey
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), key); err != nil {
			return ErrMalformedKey
		}
	default:
		return ErrUnsupportedAlgorithm
	}
	return nil
}

// Verify checks signature over message with publicKey under alg.
//
// The ES256 wire format is what WebCrypto's sign({name:'ECDSA',hash:'SHA-256'})
// emits. Both encodings it can emit are accepted, and they are told apart by
// length alone: exactly 64 bytes is a raw r||s pair, and anything else must be
// ASN.1 DER. There is no ambiguity because a DER SEQUENCE of two 32-byte
// integers is never 64 bytes long.
//
// Phase F observed the browser half of this: Chromium 158 and Firefox 153 both
// emit raw r||s (32+32) from subtle.sign, not the DER that an older reading of
// the spec suggested. A gate that accepted only DER would refuse every browser
// ES256 proof, so both are accepted and both are tested.
func Verify(alg string, publicKey, message, signature []byte) error {
	switch Algorithm(alg) {
	case AlgorithmEd25519:
		if len(publicKey) != Ed25519PublicKeySize {
			return ErrMalformedKey
		}
		if len(signature) != Ed25519SignatureSize {
			return ErrMalformedSignature
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
			return ErrInvalidSignature
		}
		return nil

	case AlgorithmES256:
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKey)
		if err != nil {
			return ErrMalformedKey
		}

		var r, s *big.Int
		if len(signature) == P256SignatureRawSize {
			r = new(big.Int).SetBytes(signature[:P256SignatureRawSize/2])
			s = new(big.Int).SetBytes(signature[P256SignatureRawSize/2:])
		} else {
			// Parse the DER pair explicitly so a malformed encoding and a
			// wrong signature are told apart.
			var sig struct{ R, S *big.Int }
			if rest, err := asn1.Unmarshal(signature, &sig); err != nil || len(rest) != 0 {
				return ErrMalformedSignature
			}
			r, s = sig.R, sig.S
		}
		if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 {
			return ErrMalformedSignature
		}

		// ECDSA verifies a digest, and WebCrypto's sign({hash:'SHA-256'})
		// hashes the message before signing it.
		digest := sha256.Sum256(message)
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return ErrUnsupportedAlgorithm
	}
}
