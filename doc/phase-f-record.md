# Phase F — verification record

Date: 2026-11-13. Cluster: k3s, Traefik 3.7.13, PostgreSQL 14.5 (CloudNativePG,
namespace `aivan-core`), gate and hud in `hermes-agent`. Recorded so Phase G does
not re-derive it.

## What was built

| Plan item | Where |
|---|---|
| F2 console mint | `internal/console/enroll.go`, `cmd/authz/main.go` (`enroll-new`) |
| F3 page | `internal/gate/web/enroll/{index.html,app.js,canonical.js}`, embedded by `internal/gate/page.go` |
| F4 claim | `internal/gate/enroll.go`, statements in `internal/store/queries.go` |
| F5 policy class | `internal/policy/policy.go` (`ClassEnrollment`, pinned to its prefix), `internal/config` |
| F6 dev mint removed | `internal/console/devsession.go`, `cmd/authz/devtools.go` and the `extraCommands` seam deleted |
| F7 tests | `internal/gate/enroll_integration_test.go`, `internal/console/enroll_integration_test.go`, `cmd/authz/enroll_integration_test.go` |
| F8 selftest | `internal/httpx/devroutes.go` + `devroutes_off.go`, `internal/gate/devvectors.go` |
| schema | `internal/store/schema/0003_enrollment.sql` |

Route registration lives in `internal/httpx/router.go`; the page and claim share
`/__aivan/enroll`, and the two assets are served from `/__aivan/enroll/`.

## Where the phase file was wrong, and what was done instead

### 1. The code cannot be 32 characters from 16 bytes

F2 says "16 random bytes", then "32 characters, 128 bits", and the example shows
`K7QM-3XZP-9WRT-4NBH` — 16 characters. Those cannot all hold: 128 bits at five
bits per Crockford character is 26 characters, and the example is 64 bits.

The entropy is the security property, so 16 bytes stayed. The code is 26
characters with a dash every four: `proof.EnrollCodeLen = 26`. The example in
the phase file is illustrative only; the tests assert the real length, and the
page states it in the hint rather than in a placeholder that clips on a phone.

### 2. WebCrypto emits raw r‖s for ES256, not DER

Phase C's C8 item asserted the ES256 wire format is ASN.1 DER and refused raw
`r||s`. Probing the browsers this phase has to support showed the opposite:

```console
$ # Chromium 158, Firefox 153, from a page over HTTPS
sign({name:'ECDSA',hash:'SHA-256'}) signature length: 64   # raw r||s, not DER
```

A gate that accepted only DER would refuse every browser's ES256 proof, which is
exactly the guaranteed fallback the page relies on when Ed25519 is unavailable.
`proof.Verify` now accepts both, told apart by length: a DER SEQUENCE of two
32-byte integers is never 64 bytes. `TestES256AcceptsRawSignature` replaces
`TestES256RejectsRawSignature` and pins both encodings; the trailing-garbage and
wrong-key refusals are unchanged. The enrollment path was then exercised end to
end with Ed25519 made unavailable, and it produced a live `es256` device.

### 3. The page's assets must be absolute

First deploy, the browser test found the claim never happened: the page was
served at `/__aivan/enroll` with `src="app.js"`, which resolves to
`/__aivan/app.js`. The script 404'd, the form submitted natively, and no claim
was posted. Fixed to `/__aivan/enroll/app.js` and
`/__aivan/enroll/canonical.js`, and pinned by
`TestEnrollPageReferencesItsOwnAssets`, which fetches every resource the page
names and refuses a relative one. The same test checks `app.js`'s own imports.

The page's inline `<link rel="icon" href="data:,">` was also blocked by the CSP
(`img-src` was not allowed); it is removed and `img-src 'self' data:` is now in
the policy.

### 4. `go:embed` cannot reach outside the package

The plan put the page in `web/enroll/` at the module root. `go:embed` patterns
may not contain `..`, so the directory is `internal/gate/web/enroll/`, embedded
by `internal/gate/page.go`. The route paths are unchanged.

### 5. The migration count tests were pinned to two versions

`TestMigrateFreshDatabase` and `TestMigrateIsSerialised` asserted exactly two
applied versions. They now compare against `store.Migrations()`, so a future
migration does not make an unrelated test fail.

## Two decisions inside the phase file's latitude

- **The origin is checked by policy, not only by the SQL predicate.** The claim
  calls the same `route()` the verify path uses and refuses unless the policy
  classifies `/__aivan/enroll` as `enrollment`. A host that serves the gate but
  was never configured for enrollment gets a `403` that names the
  misconfiguration, and no record is read. It is covered by
  `TestClaimOnAHostWithoutTheEnrollmentClassIsRefused`.
- **A 404 page is a `403`, not a `500`.** A gate built without the embedded page
  (only the health-only tests) answers `404`; a shipped binary always has it.

## Checklist

### Phase file F2 — console

- [x] `authz enroll-new --username <name> --origin <host> --kind <kind>`
      prints the code once. `TestEnrollNewPrintsACodeOnce` runs the real binary
      and asserts the code appears exactly once. `--kind` accepts `browser`,
      which is the only kind the claim endpoint serves in this phase; `phone`
      and `tablet` are refused with "no claim endpoint" rather than printing a
      code with nowhere to spend it (`TestEnrollRefusesAKindWithNoClaimEndpoint`).
- [x] Unknown user is a refusal with exit 1: `TestEnrollNewRefusesAnUnknownUser`.
- [x] `--origin` must be in `AIVAN_HOSTS`:
      `TestEnrollNewRefusesAnOriginOutsideHosts`.
- [x] A live device of that kind on that origin is refused, naming
      `authz revoke` and the device id: `TestEnrollRefusesALiveDevice`.
- [x] A live unclaimed record is refused, printing its expiry and id:
      `TestEnrollRefusesASecondLiveCode`.
- [x] 16 random bytes, Crockford base32 with dashes, display once.
- [x] Only `sha256(normalised code)` is stored:
      `TestEnrollMintsTheFirstCode` reads the row and compares the digest.
- [x] No `--show`: `TestEnrollNewHasNoShowFlag` proves the flag is a usage error
      and prints nothing.
- [x] TTL 15 minutes.
- [x] `audit_log` row naming the operator's OS user and the record:
      `TestEnrollWritesAnAuditRow`.
- [x] Lowercase and misplaced dashes normalise identically on both sides:
      `TestCodeNormalisationIsShared` claims with lowercase, stripped, spaced,
      doubled and padded spellings.

### F3/F4 — the page and the claim

- [x] One document, no framework, no CDN, no build step. The CSP is
      `default-src 'none'` plus `'self'`, and the browser run showed no
      console errors and no third-party request.
- [x] `rd` validated as a same-origin path: `/admin` is used, `//host`,
      `https://host` and `/\host` become `/`.
- [x] Key generated with `extractable: false`, and the pair asserted:
      the public half must be extractable and the private half must not, or the
      page refuses to enroll. Observed in Chromium 158: public `true`, private
      `false`.
- [x] Algorithm chosen by support: Ed25519 first, ES256 when
      `generateKey({name:'Ed25519'})` rejects. Both paths enrolled.
- [x] Private key persisted in IndexedDB as a structured clone, keyed by origin.
- [x] Claim posts, receives the cookie, navigates to `rd`.
- [x] Signature covers `code \n alg \n public_key` with fixed order and no
      trailing newline: `TestEnrollCanonicalShape` and shared vectors.
- [x] Malformed requests (`alg` outside the list, wrong key length, bad JSON,
      missing field, oversized body) are `400` and issue zero statements:
      the query counter is read in `TestUnsupportedAlgIsMalformedAndTouchesNoDatabase`
      and `TestWrongPublicKeyLengthIsMalformed`.
- [x] A bad signature is `403` and also issues zero statements:
      `TestBadSignatureTouchesNoDatabase`.
- [x] The consume is one `update … returning`; zero rows is the denial.
- [x] Device, session and audit row are inserted in the same transaction.
- [x] `Set-Cookie` is exactly Phase D's, plus identity headers, plus `201`:
      `TestClaimedSessionAuthenticatesVerify`.

### F5 — policy

- [x] `enrollment` is a class, and `/__aivan/enroll` is declared with it in
      `deploy/k8s.yaml`.
- [x] The class is refused on any other prefix: `policy.ErrEnrollmentPrefix`,
      covered by `TestRefusals` in package policy and config.

### F6 — dev mint removed

- [x] `git grep dev-session` outside `doc/` returns nothing.
- [x] `strings` on the image's binary: `dev-session` 0, `selftest` 0.
- [x] `authz dev-session` is an unknown subcommand, and `authz help` lists only
      the real commands: `TestDevSessionIsGone`.
- [x] `TestShippedBinaryHasNoSelftest` asserts the default build contains the
      enrollment path and not the selftest.

### F7 — tests and browser

- [x] **S9:** `403` for a random code with a valid signature
      (`TestS9ClaimWithAnUnknownCodeIsRefused`).
- [x] **S10:** a signature over a different code is `403`
      (`TestS10SignatureOverADifferentCodeIsRefused`); a captured claim with a
      swapped key is `403` (`TestS10CapturedClaimWithASwappedKeyIsRefused`).
- [x] **S11:** the device's `user_id` equals the record's, and a body naming a
      user is `400` (`TestS11DeviceUserComesFromTheRecord`).
- [x] Wrong origin is `403` and the record survives
      (`TestClaimForAnotherOriginIsRefused`).
- [x] Second claim of a record is `403` with exactly one device
      (`TestSecondClaimOfOneRecordIsRefused`). A variant revokes the first device
      so only the consumed-record predicate can refuse
      (`TestConsumedRecordStaysConsumedAfterRevoke`).
- [x] Two concurrent claims: one `201`, one `403`, one device, with `-race` and
      `t.Parallel` (`TestConcurrentClaimsOfOneRecord`).
- [x] Expired record is `403` (`TestExpiredRecordIsRefused`).
- [x] Unknown `alg` is `400` with no statement.
- [x] Wrong key length is `400` for four shapes, each with no statement.
- [x] Code normalisation: five spellings claim successfully.
- [x] After a claim, the cookie authenticates `/__aivan/verify` with
      `X-Aivan-Proof: session`, and the device id matches.
- [x] Every denial is one byte-identical `403`:
      `TestEnrollRejectionsAreByteIdentical` compares four refusals.

### F7 — browser, against the cluster

- [x] **Acceptance 2.** Fresh Chromium profile, `https://aivan-hud.home.arpa/admin`
      → `302` → enroll page → console code → `/admin` with the users table
      rendered. Exactly one `POST /__aivan/enroll`, no console errors, and the
      `__Host-aivan_session` cookie is set with `HttpOnly` and `Secure`.
- [x] Reload `/admin`: exactly one `POST /__aivan/enroll` total, then ordinary
      cookie requests, no signing and no nonce call.
- [x] Clear cookies but keep IndexedDB: the stored key cannot get a session by
      itself (`POST /__aivan/session` with no proof is `401`, and the page calls
      no nonce endpoint), and the enroll page is shown again. This is the known
      gap the runbook records, not a bug.
- [x] `exportKey('pkcs8' | 'raw' | 'jwk', storedKey)` each fails with
      `InvalidAccessError`; the stored `CryptoKey` reports
      `extractable: false`. Chromium 158.
- [x] A second profile's code for the same user is refused by the console,
      because one `browser` device per origin exists. The operator sees:

      ```console
      $ authz enroll-new --username chris --origin aivan-hud.home.arpa --kind browser
      enroll-new: user "chris" already has a live browser device on aivan-hud.home.arpa
      (d85b8577-41b8-dc20-e15a-c06abf093038); end it with
      `authz revoke --device d85b8577-41b8-dc20-e15a-c06abf093038` before minting another
      ```

- [x] The enrolled device survives a gate restart: `rollout restart`, then
      `/admin` from the saved browser state returns the table with no enroll
      request.
- [x] The ES256 fallback works: with `generateKey({name:'Ed25519'})` forced to
      reject, the page enrolled, and the device row is `alg = es256`.

### F8 — cross-implementation check

Both halves pass, and the check was shown to fail on drift:

```console
$ curl -s http://127.0.0.1:18080/__aivan/selftest.json
{"ok":true,"vectors":6}

$ # in a browser, on the devtools build
title: selftest: pass
PASS: 6 vectors introduced to the browser match Go.

$ # after changing canonical.js to join with CRLF
title: selftest: fail
FAIL: 6 of 6 vectors disagree.
```

`/__aivan/selftest` and `/__aivan/selftest.json` exist only under the `devtools`
tag; the shipped image contains neither string.

## Guard-removal demonstrations

Each guard was deleted, the named test was watched to fail, and the guard was
restored. These are the observations:

| Guard removed | Test | Result |
|---|---|---|
| `code_hash = $2` predicate | `TestS9ClaimWithAnUnknownCodeIsRefused` | the random code matched the only live record, so the claim reached the unique index and answered `503` instead of `403` |
| `claimed_at is null` | `TestConsumedRecordStaysConsumedAfterRevoke` | `201` on a spent record, creating a second device |
| `origin = $3` | `TestClaimForAnotherOriginIsRefused`, `TestEnrollRejectionsAreByteIdentical` | `201` on a record minted for hud, claimed on `second.home.arpa` |
| `expires_at > now()` | `TestExpiredRecordIsRefused` | `201` on an expired record |
| the whole `proof.Verify` call | `TestS10SignatureOverADifferentCodeIsRefused`, `TestS10CapturedClaimWithASwappedKeyIsRefused`, `TestBadSignatureTouchesNoDatabase` | `201` for all three |
| moving the claim before the signature check | `TestBadSignatureTouchesNoDatabase` | the query counter rose above zero before the signature was checked |

The code is inside the signed string, so a signature over a different code
cannot verify: `TestEnrollCanonicalBindsTheCode` pins that the string changes
with the code, the algorithm and the key.

## What this phase does not prove

- **No sign-in page for an already-enrolled device.** A stored key plus no cookie
  shows the enroll page, and the console refuses a second code because the first
  device is live. The recovery step is revoke-then-mint, recorded in the runbook
  handoff and in the parent plan's open list. This is the phase file's own
  deliberate omission.
- **Two hosts behind one gate.** Phase E proved a hud device is refused on a
  second host with a session; this phase's origin test is in-process. A real
  second host remains Phase G's.
- **`Sec-Fetch-Site` and CSRF from a real browser.** The claim is a JSON `fetch`
  and the session cookie requests were exercised in a browser, but the CSRF rule
  applies to state-changing gated requests, which the enrollment page does not
  make. Unchanged from Phase E.

## Recovery, for the runbook

Phase G writes `doc/runbook.md`; this is the material it needs for enrollment.

```text
# Mint the first device.
authz enroll-new --username <name> --origin <host> --kind browser
# -> one code, printed once, valid 15 minutes; enter it at
#    https://<host>/__aivan/enroll

# A person has lost their browser profile but not their account.
authz revoke --device <uuid>                                   # end the old device
authz enroll-new --username <name> --origin <host> --kind browser

# What is live.
authz list-devices --username <name>
```

Three facts the runbook has to state, because they look like faults:

1. **A refused `enroll-new` is usually correct.** "already has a live browser
   device" means the person can already sign in on that host; revoke first if
   the device is lost. "an unclaimed enrollment already exists" means a code is
   already in someone's hand; wait for the printed expiry or revoke the record.
2. **There is no sign-in page for an already-enrolled device.** A stored key
   with no cookie shows the enroll page, and the console then refuses because
   the device is still live. The recovery is revoke-then-mint, above. This is
   the phase's deliberate omission and a parent-plan open item, not a bug.
3. **The code is not recoverable.** Only its digest is stored, there is no
   `--show`, and a lost code means waiting for expiry or revoking the record.