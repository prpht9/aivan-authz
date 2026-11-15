// The login page's one script.
//
// Three cases, and the page says which one it is rather than showing a form:
//
//   this browser holds a key and the mint worked   -> to the page it was asked for
//   this browser holds a key and the mint refused  -> the device is not allowed
//   this browser holds no key                      -> enroll it, or ask for one
//
// rd arrives in the query string exactly as it does on the enrollment page, and
// is treated with the same rules: a same-origin absolute path, one leading
// slash, never a protocol-relative target.

import { reproof } from './reproof.js';

const els = {
  lede: document.getElementById('lede'),
  status: document.getElementById('status'),
  retry: document.getElementById('retry'),
  enroll: document.getElementById('enroll'),
};

// The three messages, in one place so a test can assert the exact words.
export const MESSAGES = {
  'no-key': 'This browser has no enrolled key. Enroll it, or ask to enroll it from your phone.',
  refused: 'This device is no longer allowed. Ask to enroll it again.',
  error: 'The sign-in service did not answer. Try again in a moment.',
};

// redirectTarget mirrors the enrollment page's rule. A value that fails is
// replaced with /, which is what the user gets when no rd was sent either.
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

function say(text, kind) {
  els.status.textContent = text;
  els.status.className = kind || '';
}

function showEnroll() {
  els.enroll.hidden = false;
  els.enroll.href = '/__aivan/enroll?rd=' + encodeURIComponent(target);
}

async function main() {
  els.retry.href = location.href;

  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    els.lede.textContent =
      'This browser cannot hold a key, so it cannot sign itself in.';
    say('Use a current browser over HTTPS.', 'bad');
    showEnroll();
    return;
  }

  const outcome = await reproof();

  if (outcome === 'minted') {
    say('Signed in. Opening your page…', 'good');
    location.replace(target);
    return;
  }

  if (outcome === 'refused') {
    els.lede.textContent = 'The key this browser holds was not accepted.';
    say(MESSAGES.refused, 'bad');
    showEnroll();
    return;
  }

  if (outcome === 'error') {
    els.lede.textContent = 'This browser holds a key, but the service did not answer.';
    say(MESSAGES.error, 'bad');
    els.retry.hidden = false;
    showEnroll();
    return;
  }

  // 'no-key': nothing on this device can be presented.
  els.lede.textContent = 'A key is what signs this browser in, and there is none here yet.';
  say(MESSAGES['no-key'], 'bad');
  showEnroll();
}

main();
