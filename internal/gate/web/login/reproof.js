// Re-proving the key this browser holds, and repairing a lapsed session.
//
// The enrollment page stores {deviceId, alg, key, createdAt} in IndexedDB,
// keyed by origin. This module reads that record back and mints a session with
// it: a nonce, a canonical string for POST /__aivan/session, a signature, and
// the four proof headers. A lapsed session is then a login, not a reason to
// enroll again.
//
// It is served by the gate, beside the enrollment page, and it is a module with
// no dependencies so the login page works with no internet and with the
// application scaled to zero. The application's own page imports it from here
// rather than keeping a copy, so there is one implementation of the mint order
// to drift.

import { requestCanonical, MINT_PATH, EMPTY_BODY_SHA256 } from './canonical.js';

export const DB_NAME = 'aivan-enroll';
export const STORE = 'keys';

// SIGN_PARAMS is keyed off the record's alg, which is the value the claim sent
// as devices.alg. Ed25519 signs the bytes; ES256 signs SHA-256 of them, which
// is what subtle.sign({name:'ECDSA', hash:'SHA-256'}) does.
const SIGN_PARAMS = {
  ed25519: { name: 'Ed25519' },
  es256: { name: 'ECDSA', hash: 'SHA-256' },
};

// b64url is the spelling the proof headers carry.
export function b64url(buffer) {
  let s = '';
  const view = new Uint8Array(buffer);
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    // The enrollment page creates the store. This module is the first code to
    // open the database on a browser that never enrolled, so it creates the
    // same empty store rather than failing the open.
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// storedDevice resolves to the record for this origin, or null. A browser with
// no IndexedDB, a blocked store, or a record this module cannot sign with is
// the same answer: nothing to prove with.
export async function storedDevice() {
  if (!globalThis.indexedDB) return null;
  try {
    const db = await openDB();
    const record = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(location.origin);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
    if (!record || !record.deviceId || !record.key || !SIGN_PARAMS[record.alg]) return null;
    return record;
  } catch {
    return null;
  }
}

// normalizeHost agrees with proof.NormalizeHost: lowercased, port stripped, and
// a bracketed IPv6 literal kept whole.
export function normalizeHost(host) {
  const h = String(host || '').trim();
  if (h.startsWith('[')) {
    const end = h.lastIndexOf(']');
    if (end >= 0) return h.slice(0, end + 1).toLowerCase();
  }
  const i = h.indexOf(':');
  if (i >= 0 && h.lastIndexOf(':') === i) return h.slice(0, i).toLowerCase();
  return h.toLowerCase();
}

async function nonceFor(deviceId, fetchImpl) {
  const resp = await fetchImpl('/__aivan/nonce', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device: deviceId }),
  });
  if (!resp.ok) throw new Error(`nonce answered ${resp.status}`);
  const body = await resp.json();
  if (!body || !body.nonce) throw new Error('nonce answered no nonce');
  return body.nonce;
}

// mintSession is the four calls, in order: a nonce, the canonical string, a
// signature, and the mint. It resolves to the mint's status, which is 204 when
// the cookie is set and 401 when the device is revoked or the proof did not
// verify. A nonce that failed throws: the two refusals mean different things
// and a page should not report a rate limit as a revoked device.
//
// The scheme is https because every configured host is, and the gate refuses a
// plaintext arrival before it builds a canonical string. A page served over
// http in development has no gate to sign for anyway.
export async function mintSession(record, fetchImpl) {
  const f = fetchImpl || globalThis.fetch;
  const nonce = await nonceFor(record.deviceId, f);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const canonical = requestCanonical({
    method: 'POST',
    scheme: 'https',
    host: normalizeHost(location.host),
    target: MINT_PATH,
    bodySha256: EMPTY_BODY_SHA256,
    nonce,
    timestamp,
  });
  const signature = await crypto.subtle.sign(
    SIGN_PARAMS[record.alg],
    record.key,
    new TextEncoder().encode(canonical),
  );

  const resp = await f(MINT_PATH, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'X-Aivan-Device': record.deviceId,
      'X-Aivan-Nonce': nonce,
      'X-Aivan-Signature': b64url(signature),
      'X-Aivan-Timestamp': timestamp,
    },
  });
  return resp.status;
}

/**
 * reproof is one attempt with the stored key, and it names the case so a page
 * can say which one it is without guessing:
 *
 *   'minted'  the cookie is set
 *   'no-key'  this browser holds nothing to prove with
 *   'refused' the key was presented and the gate said no
 *   'error'   the service did not answer (network, 429, 5xx)
 *
 * No retry loop. A refused nonce is a real refusal, and a retry turns a refusal
 * into load.
 */
export async function reproof() {
  const record = await storedDevice();
  if (!record) return 'no-key';
  let status;
  try {
    status = await mintSession(record);
  } catch {
    return 'error';
  }
  return status === 204 ? 'minted' : status === 401 ? 'refused' : 'error';
}

/**
 * fetchWithReproof is the wrapper an application page uses for its gated calls.
 * A gated fetch carries no proof headers, so it gets the constant 401 when the
 * session has lapsed; this re-proves the stored key and retries once. That is
 * what makes the signed-in state return without a visible login page.
 *
 * The Request is built once and cloned for the first send, so a body can be
 * sent twice; a string body cannot be reused after the first call has read it.
 * A response from the login page counts as a refusal too: the gate answers an
 * HTML navigation with a 302 there, and a followed redirect must not be
 * mistaken for the answer that was asked for.
 */
export async function fetchWithReproof(url, options) {
  const request = new Request(url, options || {});
  const response = await globalThis.fetch(request.clone());
  if (response.ok && !landedOnLogin(response)) return response;
  if (!response.ok && response.status !== 401) return response;
  if ((await reproof()) !== 'minted') return response;
  return globalThis.fetch(request);
}

function landedOnLogin(response) {
  try {
    return new URL(response.url).pathname.startsWith('/__aivan/login');
  } catch {
    return false;
  }
}
