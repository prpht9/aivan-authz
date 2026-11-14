// The gate's load profile: mixed traffic against POST /__aivan/verify.
//
// This measures the decision path, not the nonce issuance path. A nonce is
// pre-generated into the database by test/load/seed and consumed from a file
// here, so the accept case costs one verify statement and no write. Issuing a
// nonce per request would put the nonce endpoint in front of every sample and
// measure the wrong thing.
//
// The mix is the phase file's:
//
//   70% accept   — a live nonce, a real P-256 signature, expect 200
//   20% replay   — a nonce this VU already spent, expect 401
//   10% no proof — no proof headers at all, expect 401
//
// Usage:
//
//   # one line of environment for the script; the device id and the key come
//   # from the same run of the seeder
//   eval "$(go run ./test/load/seed -dsn "$MIGRATION_DSN" -user 1 -count 100000 -jwk-env)"
//   k6 run -e AIVAN_TARGET=https://aivan-hud.home.arpa \
//          -e AIVAN_NONCES=/tmp/aivan-nonces.json test/load/verify.js
//
// AIVAN_TARGET is the address the request is sent to. Through Traefik it is the
// host a browser uses; pointed at a port-forward of the gate's own Service it
// is the handler alone. The report records which was used.
//
// AIVAN_HUD_HOST is the X-Forwarded-Host the middleware sets. The default
// matches deploy/k8s.yaml and the device the seeder enrolls.
//
// TLS: the cluster's home.arpa certificate is self-signed, so a run against it
// needs K6_INSECURE_SKIP_TLS_VERIFY=true. The report says which was used.

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { Trend, Counter } from 'k6/metrics';

const TARGET = __ENV.AIVAN_TARGET || 'http://127.0.0.1:8080';
const HUD_HOST = __ENV.AIVAN_HUD_HOST || 'aivan-hud.home.arpa';

// VIA selects what the request addresses.
//
//   handler  — POST the gate's own /__aivan/verify with the forwarded headers
//              spelled out. This measures the gate's handler and nothing else.
//   traefik  — GET a gated application path and let the middleware make the
//              auth call. The signed target is that application path, which is
//              what the middleware forwards as X-Forwarded-Uri.
//
// Sending /__aivan/verify through Traefik is wrong: the gate's own router
// serves that path, so the forwarded URI would be the verify endpoint rather
// than the resource the client signed.
const VIA = __ENV.AIVAN_VIA || 'handler';
const APP_PATH = __ENV.AIVAN_PATH || '/dashboard';
const REQUEST_PATH = VIA === 'traefik' ? APP_PATH : '/__aivan/verify';
const NONCES_PATH = __ENV.AIVAN_NONCES || '/tmp/aivan-nonces.json';

// The nonce pool is read once at module scope. A file read per iteration would
// be part of the measurement.
const noncePool = JSON.parse(open(NONCES_PATH));
if (!Array.isArray(noncePool) || noncePool.length === 0) {
  throw new Error(`no nonces in ${NONCES_PATH}; run test/load/seed first`);
}

const jwkText = __ENV.AIVAN_LOAD_JWK;
if (!jwkText) {
  throw new Error('AIVAN_LOAD_JWK is not set; run test/load/seed -jwk-env and eval its output');
}
const jwk = JSON.parse(jwkText);

const deviceID = __ENV.AIVAN_LOAD_DEVICE;
if (!deviceID) {
  throw new Error('AIVAN_LOAD_DEVICE is not set; the seeder prints it as a comment line');
}

const signingKey = await crypto.subtle.importKey(
  'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'],
);

const verifyLatency = new Trend('aivan_verify_ms', true);
const accepted = new Counter('aivan_accepted');
const replayed = new Counter('aivan_replayed');
const refusedNoProof = new Counter('aivan_refused_no_proof');
// unavailable counts 503s, which the phase's acceptance forbids: a 503 is the
// gate failing to decide (database error, or the nonce table at its cap), and
// it is a different event from a refusal.
const unavailable = new Counter('aivan_unavailable');
const wrongStatus = new Counter('aivan_wrong_status');

// The last nonce each VU saw accepted, for the replay case. Keyed by VU id; a
// module-level map is safe because k6 runs one iteration per VU at a time.
const lastAccepted = {};

// EmptyBodySHA256, the digest the gate uses for a GET (internal/proof).
const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// AIVAN_PROFILE selects the shape. The default is the phase file's ramping
// profile. `steady200` holds 200 rps for the whole run, which is how the
// sustained figure in doc/latency-report.md is produced: the ramping profile
// spends most of its time below 200, so its summary mixes the ramp into the
// percentiles.
const PROFILE = __ENV.AIVAN_PROFILE || 'ramp';

const rampStages = [
  { target: 50, duration: '1m' },
  { target: 200, duration: '2m' },
  { target: 200, duration: '3m' },
  { target: 0, duration: '30s' },
];

// steadyProfile holds exactly 200 requests a second for three minutes, so the
// summary is the sustained figure and nothing else. A ramping executor spends
// its first minutes below the target, which pulls the reported average down and
// is not what "at 200 rps sustained" means.
// The constant-arrival executor is a closed model with an open pool: the
// pre-allocated VUs are created before the scenario starts, and k6 never grows
// past them for an arrival-rate executor. That is why preAllocatedVUs is sized
// for 200 rps rather than left at a number that makes the injector the
// bottleneck.
const steadyProfile = {
  executor: 'constant-arrival-rate',
  rate: Number(__ENV.AIVAN_RATE || 200),
  timeUnit: '1s',
  duration: __ENV.AIVAN_DURATION || '3m',
  // Each iteration is ~3 ms of work plus one ECDSA signature. 100 VUs at 200
  // rps needs 3-4 busy at a time; the number is the headroom for a slow
  // second, and the load run's own VU count is reported beside the latency.
  preAllocatedVUs: Number(__ENV.AIVAN_VUS || 100),
  maxVUs: Number(__ENV.AIVAN_VUS || 100),
};

// A run against a local Traefik needs the gated hostname in the Host header,
// not the address the socket dials. k6's hosts option maps the name to the
// address and keeps the name in the request, which is what the middleware
// forwards as X-Forwarded-Host. AIVAN_RESOLVE is "name:address"; unset means
// dial the URL as written.
const hostMap = {};
if (__ENV.AIVAN_RESOLVE) {
  const [name, address] = __ENV.AIVAN_RESOLVE.split(':');
  if (!name || !address) {
    throw new Error(`AIVAN_RESOLVE must be name:address, got ${__ENV.AIVAN_RESOLVE}`);
  }
  hostMap[name] = address;
}

export const options = {
  hosts: hostMap,
  scenarios: {
    steady: PROFILE === 'steady200'
      ? steadyProfile
      : {
        executor: 'ramping-arrival-rate',
        startRate: 50,
        timeUnit: '1s',
        // 100 pre-allocated VUs cover 200 rps of a millisecond request; the 500
        // ceiling absorbs a slow run without changing the arrival rate.
        preAllocatedVUs: 100,
        maxVUs: 500,
        stages: rampStages,
      },
  },
  thresholds: {
    // The phase's budget: p99 under 5 ms at the handler, under 10 ms end to
    // end. The report distinguishes the two; this is the stricter one.
    'aivan_verify_ms': ['p(50)<2', 'p(95)<4', 'p(99)<5'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// canonical builds the string the gate rebuilds. It matches internal/proof:
// version, method, scheme://host, target, body digest, nonce, timestamp, one
// per line, no trailing newline.
function canonical(method, scheme, host, target, bodyDigest, nonce, timestamp) {
  return ['aivan-v1', method, `${scheme}://${host}`, target, bodyDigest, nonce, timestamp].join('\n');
}

// b64url encodes bytes the way the gate decodes them: base64url, no padding.
function b64url(bytes) {
  const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63] + table[(n >> 6) & 63] + table[n & 63];
  }
  const left = bytes.length - i;
  if (left === 1) {
    const n = bytes[i] << 16;
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63];
  } else if (left === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += table[(n >> 18) & 63] + table[(n >> 12) & 63] + table[(n >> 6) & 63];
  }
  return out;
}

// utf8 encodes a string as bytes without TextEncoder, which k6 does not define.
function utf8(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(out);
}

async function sign(nonce, timestamp) {
  const message = canonical('GET', 'https', HUD_HOST, APP_PATH, EMPTY_BODY_SHA256, nonce, timestamp);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, utf8(message));
  return b64url(new Uint8Array(sig));
}

function headers(nonce, timestamp, signature) {
  const h = {
    'X-Aivan-Device': deviceID,
    'X-Aivan-Nonce': nonce,
    'X-Aivan-Timestamp': timestamp,
    'X-Aivan-Signature': signature,
    'Accept': 'application/json',
  };
  if (VIA !== 'traefik') {
    // A Traefik hop sets these itself; spelling them out against the handler is
    // what reproduces the request the middleware would make.
    h['X-Forwarded-Method'] = 'GET';
    h['X-Forwarded-Proto'] = 'https';
    h['X-Forwarded-Host'] = HUD_HOST;
    h['X-Forwarded-Uri'] = APP_PATH;
  }
  return h;
}

// The gate's own bound is five seconds (httpx.MaxRequestTime); waiting longer
// than that measures the timeout path rather than a decision.
const REQUEST_TIMEOUT = '5s';

// NONCE_OFFSET skips nonces an earlier run of this same pool consumed. A nonce
// is single use, so a second run against the same file would present spent
// nonces and every accept would be a nonce_unknown 401. Each run starts past
// what the previous one used; the report records the offset.
const NONCE_OFFSET = Number(__ENV.AIVAN_NONCE_OFFSET || 0);

// nextNonce takes a nonce no other iteration has taken. iterationInTest is a
// single counter across every VU, so index N is used exactly once in the run.
// That is what makes the accept case an accept: reusing an index would be a
// replay and would show up as a wrong 401.
function nextNonce() {
  return noncePool[(NONCE_OFFSET + exec.scenario.iterationInTest) % noncePool.length];
}

// note records the status of one response: a 503 is separated from the expected
// refusals so the report can say "no 503s" rather than inferring it.
function note(res, want) {
  if (res.status === 503) {
    unavailable.add(1);
  }
  if (res.status !== want) {
    wrongStatus.add(1);
  }
}

export default async function () {
  const vu = exec.vu.idInTest;
  const roll = Math.random();

  if (roll < 0.7) {
    const nonce = nextNonce();
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await sign(nonce, timestamp);
    const res = http.get(`${TARGET}${REQUEST_PATH}`, { headers: headers(nonce, timestamp, signature), timeout: REQUEST_TIMEOUT });
    verifyLatency.add(res.timings.duration);
    accepted.add(1);
    lastAccepted[vu] = nonce;
    note(res, 200);
    check(res, { 'accept is 200': (r) => r.status === 200 });
    return;
  }

  if (roll < 0.9) {
    // Replay a nonce this VU has already spent. A VU that has not accepted yet
    // spends one first, so the case stays a real replay.
    let nonce = lastAccepted[vu];
    const timestamp = String(Math.floor(Date.now() / 1000));
    if (!nonce) {
      nonce = nextNonce();
      const first = await sign(nonce, timestamp);
      http.get(`${TARGET}${REQUEST_PATH}`, { headers: headers(nonce, timestamp, first), timeout: REQUEST_TIMEOUT });
    }
    const signature = await sign(nonce, timestamp);
    const res = http.get(`${TARGET}${REQUEST_PATH}`, { headers: headers(nonce, timestamp, signature), timeout: REQUEST_TIMEOUT });
    replayed.add(1);
    note(res, 401);
    check(res, { 'replay is 401': (r) => r.status === 401 });
    return;
  }

  // No proof at all: a navigation with no device and no cookie.
  const bare = { 'Accept': 'application/json' };
  if (VIA !== 'traefik') {
    bare['X-Forwarded-Method'] = 'GET';
    bare['X-Forwarded-Proto'] = 'https';
    bare['X-Forwarded-Host'] = HUD_HOST;
    bare['X-Forwarded-Uri'] = APP_PATH;
  }
  const res = http.get(`${TARGET}${REQUEST_PATH}`, { headers: bare, timeout: REQUEST_TIMEOUT });
  refusedNoProof.add(1);
  note(res, 401);
  check(res, { 'no proof is 401': (r) => r.status === 401 });
}
