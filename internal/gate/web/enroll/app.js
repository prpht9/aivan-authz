// The enrollment page's one script.
//
// It generates a key the page cannot export, signs the claim, and exchanges it
// for a session cookie. Everything it needs is in this directory: no framework,
// no CDN, no build step, so the page works on a LAN with no internet.
//
// The private key is a non-extractable CryptoKey stored in IndexedDB as a
// structured clone. It never leaves the browser, and this script cannot read its
// bytes even if it wanted to. The public half is exported and sent.

import { normalizeCode, validCode, CODE_LEN, enrollCanonical } from '/__aivan/enroll/canonical.js';

const DB_NAME = 'aivan-enroll';
const STORE = 'keys';
const CODE_BLOCK = 4;

const els = {
  form: document.getElementById('enroll'),
  code: document.getElementById('code'),
  go: document.getElementById('go'),
  status: document.getElementById('status'),
  meta: document.getElementById('meta'),
};

// ---------------------------------------------------------------------------
// Redirect target
//
// rd arrives in the query string and is used as a navigation target after the
// claim succeeds. It must be a same-origin absolute path: one leading slash and
// not two, so it can never become a protocol-relative //host URL. A value that
// fails is replaced with /, which is what the user gets when no rd was sent
// either.
// ---------------------------------------------------------------------------
function redirectTarget() {
  const rd = new URLSearchParams(location.search).get('rd');
  if (!rd) return '/';
  if (!rd.startsWith('/')) return '/';
  if (rd.startsWith('//')) return '/';
  if (rd.startsWith('/\\')) return '/';       // browsers read /\host as //host
  if (rd.includes('\n') || rd.includes('\r')) return '/';
  return rd;
}

const target = redirectTarget();

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------
function say(text, kind) {
  els.status.textContent = text;
  els.status.className = kind || '';
}

function busy(on) {
  els.go.disabled = on;
  els.form.setAttribute('aria-busy', on ? 'true' : 'false');
}

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------
function b64url(bytes) {
  let s = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Algorithm choice
//
// Chosen by support, not by a preference list in code: Ed25519 where the
// runtime generates it, ES256 otherwise. Both are on the gate's fixed list.
// ---------------------------------------------------------------------------
async function chooseAlgorithm() {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return { name: 'Ed25519', wire: 'ed25519' };
  } catch {
    return { name: 'ECDSA', namedCurve: 'P-256', wire: 'es256' };
  }
}

const SIGN_PARAMS = {
  ed25519: { name: 'Ed25519' },
  es256: { name: 'ECDSA', hash: 'SHA-256' },
};

// ---------------------------------------------------------------------------
// Key generation
//
// One call with extractable: false. Per the WebCrypto spec the public half is
// always extractable and only the private half inherits the flag, so this is
// asserted rather than assumed. A runtime that makes the public half
// non-extractable cannot be used: the page would have no key to send, and
// silently generating an extractable private key would give up the property the
// whole design rests on. Such a browser is refused, with the reason shown.
// ---------------------------------------------------------------------------
async function generateKey(choice) {
  const params = choice.wire === 'ed25519'
    ? { name: 'Ed25519' }
    : { name: 'ECDSA', namedCurve: 'P-256' };

  const pair = await crypto.subtle.generateKey(params, false, ['sign', 'verify']);
  if (pair.publicKey.extractable !== true || pair.privateKey.extractable !== false) {
    throw Object.assign(new Error('noncompliant'), {
      noncompliant: true,
      detail: `public extractable=${pair.publicKey.extractable}, private extractable=${pair.privateKey.extractable}`,
    });
  }
  const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
  return { pair, publicKey: b64url(raw) };
}

// ---------------------------------------------------------------------------
// IndexedDB
//
// A non-extractable CryptoKey cannot go in localStorage, but it can be stored
// in IndexedDB as a structured clone. Keeping it keyed by origin is what makes
// a second visit not need the code again. The stored record also carries the
// device id and algorithm the key belongs to.
// ---------------------------------------------------------------------------
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function loadStored() {
  try {
    const db = await openDB();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(location.origin);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function storeKey(record) {
  const db = await openDB();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(record, location.origin);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------
async function claim(code, choice, key) {
  const canonical = enrollCanonical(code, choice.wire, key.publicKey);
  const signature = await crypto.subtle.sign(
    SIGN_PARAMS[choice.wire], key.pair.privateKey, new TextEncoder().encode(canonical));

  const resp = await fetch('/__aivan/enroll', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      kind: 'browser',
      alg: choice.wire,
      public_key: key.publicKey,
      signature: b64url(signature),
    }),
  });
  return resp;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  // Pre-fill from ?code=, which is how an operator hands over a code without a
  // copy-paste race, and how a scanned square lands here. It is not an
  // authority: the claim still has to verify.
  //
  // The code is a live single-use secret, so it is scrubbed from the address
  // bar as soon as it is read. history.replaceState leaves no entry for it, so
  // a reload, a bookmark or a browser history screen cannot replay it, and the
  // page keeps no copy beyond the field the person can already see.
  const params = new URLSearchParams(location.search);
  const prefill = params.get('code');
  if (prefill) {
    els.code.value = prefill;
    params.delete('code');
    const rest = params.toString();
    history.replaceState(null, '',
      location.pathname + (rest ? '?' + rest : '') + location.hash);
  }

  if (!window.crypto || !window.crypto.subtle) {
    // No WebCrypto means no key this page can defend. Say so plainly; an
    // HTTP origin, or a very old browser, lands here.
    say('This browser cannot generate a key, so it cannot enroll. ' +
        'Use a current browser over HTTPS.', 'bad');
    els.go.disabled = true;
    return;
  }

  const stored = await loadStored();
  els.meta.textContent = stored
    ? `This browser already holds a key from ${new Date(stored.createdAt).toLocaleString()}.`
    : '';

  els.form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (els.go.disabled) return;

    const code = normalizeCode(els.code.value);
    if (!validCode(code)) {
      say(`That does not look like an enrollment code. Enter all ${CODE_LEN} characters.`, 'bad');
      els.code.focus();
      return;
    }

    busy(true);
    say('Generating a key for this browser…');

    try {
      const choice = await chooseAlgorithm();
      const key = await generateKey(choice);

      say('Claiming the enrollment…');
      const resp = await claim(code, choice, key);

      if (resp.status === 201) {
        const body = await resp.json().catch(() => ({}));
        await storeKey({
          deviceId: body.device_id || '',
          alg: choice.wire,
          key: key.pair.privateKey,
          createdAt: Date.now(),
        });
        say('Enrolled. Opening your page…', 'good');
        location.replace(target);
        return;
      }

      if (resp.status === 403) {
        // One message for every refusal: the code is wrong, used, or expired,
        // or it was minted for another application. The page cannot tell them
        // apart, and saying so would only guess.
        say('That enrollment was refused. The code may be wrong, already used ' +
            'or expired. Ask for a new code.', 'bad');
      } else if (resp.status === 400) {
        say('The request was not accepted. This browser may store keys ' +
            'differently; try a current Chrome, Firefox or Safari.', 'bad');
      } else {
        say(`The service answered ${resp.status}. Try again in a moment.`, 'bad');
      }
    } catch (err) {
      if (err && err.noncompliant) {
        say('This browser reports an exportable key pair, which this page ' +
            'will not enroll (it ' + err.detail + '). Use a current browser.', 'bad');
        els.go.disabled = true;
        return;
      }
      say('This browser could not create the key. Use a current browser over ' +
          'HTTPS.', 'bad');
      console.error(err);
    } finally {
      busy(false);
    }
  });

  els.code.focus();
}

main();