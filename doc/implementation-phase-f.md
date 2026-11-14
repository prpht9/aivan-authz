# Phase F — enrollment

Status: complete (2026-11-13).

Standalone work file. Prerequisites: Phase E complete (aivan-hud is behind the
gate with a console-minted session). No other phase file needed.

Parent plan: `doc/aivan-initial-plan.md` §5.7, §8 Phase F, §9. Spec:
`doc/aivan-initial-spec.md` §6.4, §6.5, §9 (S9, S10, S11), §11 (acceptance 2).

**Goal:** a browser generates a key it cannot export, proves possession of it,
and receives a session — with no open registration path and no way for a
captured request to be reused. This phase removes the console mint from
Phase E.

## F1. Why the claim is signed

Enrollment is the one moment an unauthenticated client is given authority. Three
failure modes are closed structurally, not by checks:

| Attack | Closed by |
|---|---|
| Stranger claims an enrollment meant for someone else | No pending record, no device; records are minted only from the console |
| Captured claim POST replayed with a different key | The signature covers `code` and `public_key` together |
| Guessed code with an attacker's own key | A signature over the code must verify against the submitted key |
| Code minted for one application spent on another | `pending_enrollments.origin` matched against `X-Forwarded-Host` |
| Two claims racing for one record | `update … where claimed_at is null returning` |

The consequence worth stating: the claiming device never asserts who it is. The
user comes from the pending record, and the key is proven by the signature.

## F2. Console: mint a pending enrollment

```text
authz enroll-new --username <name> --origin <host> --kind <kind>
```

- Resolves `--username` to a `user_id` against `public.users`. Unknown user is a
  refusal with a non-zero exit; the console may be explicit, unlike HTTP.
- `--origin` must be one of `AIVAN_HOSTS`.
- Refuses if an unclaimed, unexpired record already exists for that user, origin
  and kind, and prints the existing record's expiry so the operator knows to wait
  or revoke it.
- Refuses if that user already has a live device of that kind on that origin,
  matching the partial unique index.
- Generates 16 random bytes, displays as Crockford base32 with a dash after every
  four characters, e.g. `K7QM-3XZP-9WRT-4NBH`. 32 characters, 128 bits.
- Stores `sha256(code)` only. Prints the code once, with no re-print path:
  a `--show` flag must not exist.
- TTL 15 minutes.
- Appends an `audit_log` row naming the operator's OS user and the record id.

The code is typed by a human from one screen to another, so lowercase input and
dashes in the wrong place must be normalised before hashing: uppercase, strip
everything that is not `[A-Z0-9]`, then compare. Normalise before hashing on
both sides or the claim fails confusingly.

## F3. The page

`web/enroll/index.html` plus `web/enroll/app.js`, embedded with `go:embed`.
Served at `GET /__aivan/enroll`.

- One document, no framework, no CDN, no build step. It must work on a LAN with
  no internet.
- Reads `rd` from the query string and validates it is a same-origin path
  starting with `/` and not `//`, before using it as a redirect target. A `rd`
  that fails is replaced with `/`.
- Shows three fields: the code (pre-filled from `code` if present), and the
  algorithm choice presented as "this device" rather than a crypto term.
- Generates the key with `extractable: false`. Per the WebCrypto spec the public
  half is always extractable and only the private half inherits the flag, so a
  single call gives a non-extractable private key and an exportable public key.
  Assert that rather than assume it — `keyPair.publicKey.extractable` must be
  `true` and `keyPair.privateKey.extractable` must be `false`. If the public half
  reports `false`, the runtime is non-compliant and the private key cannot be
  defended by this route; refuse to enroll on that browser and say so, rather
  than silently generating an extractable key.
- Chooses the algorithm by support, not by preference ordering in code:
  ```js
  let alg = 'es256';
  try {
    await crypto.subtle.generateKey({name:'Ed25519'}, false, ['sign','verify']);
    alg = 'ed25519';
  } catch { /* P-256 below */ }
  ```
  Ed25519 first, ES256 as the guaranteed fallback. Both are on the fixed list.
- Persists the private key. A non-extractable `CryptoKey` cannot be stored in
  `localStorage` but can be stored in IndexedDB as a structured-clone value.
  Keep `{deviceId, alg, key}` there, keyed by origin. This is what makes the
  second visit not need the code again.
- Posts the claim, receives a session cookie, then navigates to `rd`.

The page renders nothing from the application and holds no application data. It
is the single UI permitted by spec §10 as amended.

## F4. The claim

```text
POST /__aivan/enroll
Content-Type: application/json

{ "code": "K7QM3XZP9WRT4NBH", "kind": "browser", "alg": "es256",
  "public_key": "<base64url raw>" }

signature over:
  aivan-enroll-v1 \n code \n alg \n public_key
```

`signature` is base64url and unpadded, over the UTF-8 bytes of that string with
`code` normalised and `public_key` as sent. Fixed field order, single `\n`,
no trailing newline — same discipline as the request canonical string.

Server order:

1. Parse and normalise. Reject unknown `kind`, unknown `alg`, a public key of the
   wrong length for the algorithm, and a code that is not 32 characters after
   normalisation.
2. Verify the signature against the submitted public key. Self-contained, so a
   bad signature never touches the database and reveals nothing.
3. Generate the device id.
4. One transaction:
   ```sql
   update authz.pending_enrollments
      set claimed_at = now(), claimed_device_id = $1
    where code_hash = sha256($2)
      and origin    = $3
      and claimed_at is null
      and expires_at > now()
   returning user_id, origin, kind;
   ```
   Zero rows means a denial. Insert the device from the returned row, using the
   returned `kind` and the request's `alg` and key. Insert the session. Commit.
5. `Set-Cookie` exactly as Phase D does, plus the identity headers and a `201`
   with `{device_id, user_id, username}`.
6. `audit_log` row: `decision=enroll`, `reason=claimed`, device id, user id,
   origin.

All denials on this route are one `403` with one body. A wrong code, an expired
record, a claimed record, and a wrong-origin claim must be indistinguishable.

Unknown `alg` is `400`, not `403`, because it is a malformed request and leaks
nothing. Keep that distinction deliberate.

## F5. Policy class

Add `enrollment` to the policy classes and point `/__aivan/enroll` at it. The
route accepts no user proof and requires only that the body carries a claim. It
is reachable only on the gate router, so the `Public`-class warning about a
path reaching the gate does not apply.

Config refuses `enrollment` on any prefix other than `/__aivan/enroll`.

## F6. Remove the console mint

- Delete the `devtools`-tagged file from Phase E and any flag it introduced.
- Delete the reference from Phase E's checklist and any README step.
- `git grep dev-session` returns nothing.
- The image no longer contains it: rebuild and confirm with
  `strings /authz | grep -c dev-session` returning 0, or check the build tags in
  the Dockerfile.

That sequence matters: enrollment must be proven working *before* the mint is
removed, otherwise the only way into the system disappears with it.

## F7. Tests

Integration:

- [ ] **S9:** claim with a random code and a valid signature — `403`.
- [ ] **S10:** claim with a valid code, valid key, and signature over a
      *different* code — `403`.
- [ ] **S11:** a claim whose pending record names user A cannot produce a device
      for user B. Assert the inserted row's `user_id` equals the record's. There
      is no request field for user, so the test asserts the absence of one.
- [ ] Wrong origin: a code minted for `aivan-hud.home.arpa` claimed with
      `X-Forwarded-Host: aivan-site.home.arpa` — `403`.
- [ ] Second claim of the same record — `403`, and exactly one device exists.
- [ ] Two concurrent claims of the same record — one `201`, one `403`, one
      device. Run the test with `-race` and with `t.Parallel`.
- [ ] Expired record (injected clock) — `403`.
- [ ] `alg` not in the list — `400` and no database statement, asserted with the
      query counter.
- [ ] A key of the wrong length for `alg` — `400`.
- [ ] Code normalisation: lowercase and stray dashes still claim successfully.
- [ ] After a successful claim, the cookie authenticates `/__aivan/verify` with
      `X-Aivan-Proof: session`, and the device id matches.

Browser, against the cluster:

- [ ] Fresh profile, `https://aivan-hud.home.arpa/admin` → `302` → enroll page →
      paste a console-minted code → lands back on `/admin` with the table
      rendered. **Acceptance 2.**
- [ ] Reload `/admin` with DevTools: exactly one `POST /__aivan/enroll`, then
      ordinary requests with the cookie and no further signing.
- [ ] Clear cookies but keep IndexedDB: the stored key cannot by itself get a
      session (no nonce endpoint is called by the page yet), and the enroll page
      is shown again. Record this behaviour; it is a known gap, not a bug, until
      a sign-in page exists.
- [ ] In DevTools, `crypto.subtle.exportKey('pkcs8', key)` on the stored private
      key fails, proving non-extractability. If it succeeds, the browser is
      non-compliant and the phase's page must have refused; note which browser
      and version.
- [ ] A second browser profile claims a second code for the same user: refused
      by the console mint, because one `browser` device per origin already
      exists. Record the message the operator sees.

## F8. Cross-implementation canonical test

The enroll claim and the request canonical string are built in both Go and
JavaScript. Add a small check that runs in the browser during a test build and
compares against `internal/proof/testdata/canonical.json`:

```text
GET /__aivan/selftest  -> 500 if any vector mismatches, 200 ok otherwise
```

Built only with the `devtools` tag, and deleted in Phase G along with the rest.
The point is that a drift between the two implementations fails a test rather
than a user.

## F9. Exit criteria

- [ ] S9, S10, S11 green, each demonstrated to fail without its guard.
- [ ] Acceptance 2 observed in a real browser on the cluster from an empty
      profile.
- [ ] Console mint deleted and unreachable from the image.
- [ ] Every denial on `/__aivan/enroll` is one byte-identical `403`.
- [ ] `GET /__aivan/selftest` passes, then is removed.
- [ ] Commit in `aivan-authz`; no application change needed.

## Handoff to Phase G

Phase G is hardening: it needs the full path in place to attack it. It will add
the purge job this phase relies on for nonce and session table growth, the
`413` body test, the load profile, and the runbook that starts with
`enroll-new`.

Deliberate omission: no sign-in page for an already-enrolled device. A stored
key plus no cookie currently means re-enrolling, which the console refuses. That
gap is real; record it in the runbook as the current recovery step (revoke, then
mint) rather than hiding it. A dedicated sign-in route is the natural next
feature and is listed as open in the parent plan.