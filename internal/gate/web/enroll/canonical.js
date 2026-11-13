// The enrollment claim's canonical string and the code's reading rules.
//
// This file is the browser half of internal/proof/enroll.go. Both are tested
// against internal/proof/testdata/enroll.json, so a drift between them fails a
// test rather than refusing a user. It is a module with no dependencies so the
// page works with no network at all.

export const ENROLL_VERSION = 'aivan-enroll-v1';

// Crockford base32, without I, L, O and U.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// The same 26 characters the Go side calls proof.EnrollCodeLen: 16 random bytes
// at five bits per character.
export const CODE_LEN = 26;

// normalizeCode is the reading rule: uppercase, I and L as 1, O as 0, and every
// other non-alphanumeric character dropped. It has to agree with
// proof.NormalizeEnrollCode character for character, because the digest of the
// result is what the database compares.
export function normalizeCode(raw) {
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    let c = raw.charCodeAt(i);
    if (c >= 0x61 && c <= 0x7a) c -= 0x20;            // a-z to A-Z
    if (c >= 0x30 && c <= 0x39) {                     // 0-9
      out += String.fromCharCode(c);
    } else if (c >= 0x41 && c <= 0x5a) {              // A-Z
      if (c === 0x49 || c === 0x4c) out += '1';       // I, L
      else if (c === 0x4f) out += '0';                // O
      else out += String.fromCharCode(c);
    }
    // Everything else is a separator or a keyboard accident.
  }
  return out;
}

// validCode reports whether a normalised code is the shape the console mints.
export function validCode(code) {
  if (code.length !== CODE_LEN) return false;
  for (let i = 0; i < code.length; i++) {
    if (ALPHABET.indexOf(code[i]) < 0) return false;
  }
  return true;
}

// enrollCanonical is the exact string a device signs to claim an enrollment.
//
// code must already be normalised; publicKey is the base64url spelling sent in
// the request, unchanged. Single newlines, no trailing newline, fixed field
// order.
export function enrollCanonical(code, alg, publicKey) {
  return [ENROLL_VERSION, code, alg, publicKey].join('\n');
}