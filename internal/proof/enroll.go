package proof

import (
	"strings"
)

// Enrollment wire format. The claim is self-contained: the signature covers the
// code, the algorithm and the public key together, so a captured request cannot
// be repurposed with a different key and a guessed code cannot be spent without
// the matching key. The browser builds the same string in web/enroll/canonical.js
// and testdata/enroll.json is what both are tested against.
const (
	// EnrollVersion is the first line of the enrollment claim. It is a
	// different version from Version because the two strings are different
	// messages; a device proof can never be replayed as an enrollment claim.
	EnrollVersion = "aivan-enroll-v1"

	// EnrollCodeBytes is the entropy of a pending code. 128 bits is far past
	// what a 15-minute single-use secret needs, and it is why the lookup does
	// not need a constant-time comparison.
	EnrollCodeBytes = 16

	// EnrollCodeLen is the length of the normalised code in Crockford base32:
	// 128 bits at five bits per character is 26 characters. The phase file
	// says "32 characters" and shows a 16-character example; neither is
	// reachable from 16 bytes at base32, and 26 is what the stated entropy
	// implies. doc/phase-f-record.md records the discrepancy.
	EnrollCodeLen = 26

	// crockfordAlphabet excludes I, L, O and U: the first three are read as 1
	// and 0, and U is excluded so a code cannot spell a rude word.
	crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// EnrollCanonical returns the exact bytes a device signs to claim a pending
// enrollment, in the fixed field order.
//
// code must already be normalised (NormalizeEnrollCode); publicKey is the
// base64url spelling the request carries, unchanged. The separator is a single
// newline and there is no trailing newline, the same discipline as Canonical.
func EnrollCanonical(code, alg, publicKey string) string {
	var b strings.Builder
	b.Grow(96)
	b.WriteString(EnrollVersion)
	b.WriteByte('\n')
	b.WriteString(code)
	b.WriteByte('\n')
	b.WriteString(alg)
	b.WriteByte('\n')
	b.WriteString(publicKey)
	return b.String()
}

// NormalizeEnrollCode makes a code typed from one screen to another compare
// equal to the one that was minted.
//
// The rules are the Crockford reading rules on top of the phase file's
// "uppercase, strip everything that is not [A-Z0-9]":
//
//   - ASCII uppercase, so a keyboard with caps lock on still works.
//   - I and L become 1, and O becomes 0, because those are the characters a
//     human confuses and Crockford base32 already declines to use.
//   - Every other non-alphanumeric character is dropped: dashes in the wrong
//     place, spaces, and a stray newline from a copy-paste.
//
// The result is compared by equality against a stored digest, so both sides
// must normalise identically. ValidEnrollCode then rejects a string that is the
// wrong length or uses a character the alphabet excludes, which is a malformed
// request (400) and reveals nothing about any record.
func NormalizeEnrollCode(raw string) string {
	var b strings.Builder
	b.Grow(EnrollCodeLen)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			switch c {
			case 'I', 'L':
				b.WriteByte('1')
			case 'O':
				b.WriteByte('0')
			default:
				b.WriteByte(c)
			}
		default:
			// A separator or anything else a keyboard produced. The code is
			// fixed length, so dropping it cannot turn one code into another.
		}
	}
	return b.String()
}

// ValidEnrollCode reports whether a normalised code is the shape a mint writes:
// exactly EnrollCodeLen characters, all from the Crockford alphabet.
func ValidEnrollCode(normalized string) bool {
	if len(normalized) != EnrollCodeLen {
		return false
	}
	for i := 0; i < len(normalized); i++ {
		if strings.IndexByte(crockfordAlphabet, normalized[i]) < 0 {
			return false
		}
	}
	return true
}

// EncodeEnrollCode renders raw bytes as the displayed code: Crockford base32,
// uppercase, with a dash after every four characters. Extra dashes and lowercase
// letters survive NormalizeEnrollCode, so the display form is free to change.
func EncodeEnrollCode(raw []byte) string {
	// Five bits per character, most significant first. The accumulator keeps
	// at most 12 bits (7 carried plus 8 appended), so one byte at a time is
	// all the masking it needs.
	var (
		out   strings.Builder
		acc   uint
		bits  uint
		chars int
	)
	emit := func(v byte) {
		if chars > 0 && chars%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(crockfordAlphabet[v])
		chars++
	}
	for _, by := range raw {
		acc = acc<<8 | uint(by)
		bits += 8
		for bits >= 5 {
			bits -= 5
			emit(byte((acc >> bits) & 0x1f))
		}
		acc &= (1 << bits) - 1
	}
	if bits > 0 {
		// Left-align the leftover bits with zero padding. The code is compared
		// as text and never decoded back to bytes, so the padding need not be
		// reversible.
		emit(byte((acc << (5 - bits)) & 0x1f))
	}
	return out.String()
}
