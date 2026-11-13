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

// Verify checks signature over message with publicKey under alg.
//
// The ES256 wire format is ASN.1 DER, because that is what WebCrypto's
// sign({name:'ECDSA',hash:'SHA-256'}) emits. A raw r||s signature is refused:
// accepting both encodings would leave one of them untested.
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
		// Parse the DER pair explicitly so a malformed encoding and a wrong
		// signature are told apart. A raw r||s value fails here.
		var sig struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(signature, &sig); err != nil || len(rest) != 0 {
			return ErrMalformedSignature
		}
		// ECDSA verifies a digest, and WebCrypto's sign({hash:'SHA-256'})
		// hashes the message before signing it.
		digest := sha256.Sum256(message)
		if sig.R == nil || sig.S == nil || !ecdsa.Verify(pub, digest[:], sig.R, sig.S) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return ErrUnsupportedAlgorithm
	}
}
