// The canonical request string, for the browser half of a session mint.
//
// This file is the browser twin of internal/proof/canonical.go. The format is
// declared in exactly one Go place and the constants that decide whether a
// signature can ever match are asserted against this source by
// TestLoginCanonicalConstantsMatch, so a change to one side fails a test rather
// than a user's sign-in.
//
// It is a module with no dependencies so the pages work on a LAN with no
// internet.

export const REQUEST_VERSION = 'aivan-v1';

// The path a mint proof must cover. The gate pins the signed method and target
// to this endpoint (mintPath in internal/gate/session.go), so a proof captured
// for an application route cannot be replayed to mint a cookie.
export const MINT_PATH = '/__aivan/session';

// sha256 of zero bytes, which is the digest a bodyless mint carries.
export const EMPTY_BODY_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// requestCanonical is the exact string a device signs, single newlines and no
// trailing newline, in the fixed field order of proof.Canonical.
//
// r is { method, scheme, host, target, bodySha256, nonce, timestamp }.
export function requestCanonical(r) {
  return [
    REQUEST_VERSION,
    r.method,
    `${r.scheme}://${r.host}`,
    r.target,
    r.bodySha256,
    r.nonce,
    r.timestamp,
  ].join('\n');
}
