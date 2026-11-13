# Phase D — verification record

Date: 2026-11-13. Recorded so Phase E does not have to re-derive it.

Checked on a throwaway PostgreSQL 18.6 cluster (`initdb` in `/tmp`, port
55432), Go 1.26.5, this machine.

## What was built

| Plan item | Where |
|---|---|
| D2 minting | `internal/gate/session.go` (`mintSession`, `insertSession`) |
| D3 reading the cookie | `internal/gate/session.go` (`verifySession`, `readSession`) |
| D3 statements | `internal/store/queries.go` (`SessionMintSQL`, `SessionReadSQL`, `SessionDeleteSQL`) |
| D4 policy and header differences | `internal/gate/verify.go` (path split), `internal/gate/session.go` (`ProofSession`) |
| D5 CSRF | `internal/gate/session.go` (`csrfRefusal`, `validCSRFToken`) |
| D6 logout, revoke, list-devices | `internal/gate/session.go` (`logout`), `internal/console/console.go` |
| D7 tests | `internal/gate/session_integration_test.go`, `internal/gate/session_test.go`, `internal/console/console_integration_test.go` |

Files changed outside the new code: `internal/httpx/router.go` mounts
`/__aivan/session`; `internal/gate/verify.go` gains `proofIdentity` and `allow`
so the proof path and the mint share one signature check and one header writer,
and gains the cookie branch in `Verify`; `cmd/authz/main.go` adds
`list-devices` and `revoke`; `deploy/k8s.yaml` names the session lifetimes.

## Checklist, with what was observed

Cookie minting and reading:

- [x] A mint with no proof, a bad signature or an expired nonce is a 401 and
      writes no row and no cookie.
- [x] The cookie is asserted as a whole string:
      `__Host-aivan_session=<43 chars>; Path=/; Secure; HttpOnly; SameSite=Lax`,
      with no `Domain`, no `Max-Age` and no `Expires`.
- [x] A minted cookie authenticates `/__aivan/verify` with
      `X-Aivan-Proof: session`, the right user, device id, device kind and
      `admin,free` roles, and the same policy evaluation applies (`/admin` is
      403 for a user without the role).
- [x] `authz.sessions.token_hash` is the SHA-256 of the token text, asserted by
      querying for the token as bytes and finding nothing. The token does not
      appear in the decision log.
- [x] A session past `idle_expires_at` is refused; one past
      `absolute_expires_at` is refused even with its idle window open.
- [x] The insert stamps `devices.last_seen_at` in the same statement.
- [x] A malformed cookie (wrong length, padding, a non-base64url character) is
      treated as no credential and reaches the database zero times.
- [x] The mint proof must cover `POST /__aivan/session`: a proof made for
      `GET /dashboard` is refused even with forwarded headers that agree with
      it, so a captured application proof cannot be traded for a cookie.
- [x] Only `POST` and `DELETE` are answered; others are `405` with
      `Allow: POST, DELETE`.

S5 and S13:

- [x] **S5:** a device revoked after its cookie was minted is refused on the
      next request, with a body byte-identical to an expired session's.
- [x] **S5** through the console: `authz revoke --device` deleted the live
      session in the same transaction, wrote the audit row, and `list-devices`
      then showed `REVOKED` set. The live cookie was refused afterwards.
- [x] **S13:** unsafe method with no `Sec-Fetch-Site` and no `X-Aivan-Csrf` is
      `403 csrf_missing`; `same-site` is `403 csrf_samesite`; `same-origin` and
      `none` pass; a header matching `^[A-Za-z0-9_-]{16,128}$` passes; 15
      characters, 129 characters and a bad character are `403`; a 128-character
      header passes.
- [x] A request with both a cookie and a valid signed proof is the proof path
      and reports `X-Aivan-Proof: nonce`, so it skips CSRF.
- [x] Deactivating a user ends their live session on the next request, and
      reactivating restores the same one, because nothing deleted the row.

Budget and transaction:

- [x] A session-authenticated verify is exactly one statement, asserted on the
      pool counter. Measured against the proof path:
      `proof p50=4.96ms p99=5.83ms`, `session p50=423µs p99=590µs` — the same
      round trip, less CPU because no signature is verified.
- [x] The 60 s write window: with `idle_expires_at` 30 s ahead, a verify leaves
      the value unchanged; with it 90 s ahead, the verify moves it to
      `now + 15m`. Both verifies are one statement either way.
- [x] Revoke is one transaction. A child process was SIGKILLed between
      `revoked_at` and the session delete; afterwards the database held neither
      a revoked device nor a deleted session, and a retry completed the revoke.
- [x] Logout deletes the row and returns
      `Set-Cookie: __Host-aivan_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
      a second logout, and a logout with no cookie, are both `204`.
- [x] `go vet ./...` and `gofmt -l .` are clean.
- [x] Race detector clean over the functional tests
      (`go test -race -short ./internal/gate/`).

## Guard removal, one at a time

Each row is a temporary edit, the test it broke, and what was deleted. The
script that did it is not committed; the tree was restored after each run.

| Requirement | Guard temporarily removed | Test that failed |
|---|---|---|
| S5 | `case row.revokedAt != nil` on the session path | `TestS5RevokeKillsTheLiveSession` |
| S5 | `case !row.userActive` on the session path | `TestSessionRefusesDeactivatedUser` |
| S13 | the `csrfRefusal` call before the allow | `TestS13CSRF` |
| S13 | `case "same-site": return ReasonCSRFSite` | `TestS13CSRF` |
| one statement | an extra `select 1` before the session read | `TestSessionVerifyIsOneStatement` |
| idle window | the `case ... interval '60 seconds'` in `SessionReadSQL` | `TestSessionVerifyIsOneStatement` |
| absolute cap | `and s.absolute_expires_at > now()` | `TestSessionAbsoluteExpiry` |
| idle expiry | `and s.idle_expires_at > now()` | `TestSessionIdleExpiry` |
| session origin | `and d.origin = $3` in `SessionReadSQL` | `TestSessionIsScopedToItsOrigin` |
| mint path binding | `f.Method = POST; f.Target = mintPath` | `TestMintProofMustCoverTheMintPath` |
| mint signature | the `proof.Verify` refusal in `proofIdentity` | `TestMintRequiresAValidProof` |
| proof beats cookie | `if anyProofHeader(r)` in `Verify` | `TestProofBeatsCookieForCSRF` |
| cookie attributes | `Secure; HttpOnly` dropped from the mint cookie | `TestMintCookieHeaderIsExact` |
| revoke transaction | `tx.Commit` between `revoked_at` and the delete | `TestRevokeIsTransactionalAcrossACrash` |

## Findings that changed the plan's assumptions

**The plan's statement needs the device's origin as a predicate.** D3 selects
`d.origin` but does not filter on it. The `__Host-` cookie already cannot cross
hosts in a conforming browser, but the server's half was missing: a cookie
presented to a second configured host would have authenticated there if the
browser could be made to send it. The read statement now joins
`on d.id = t.device_id and d.origin = $3`, and `TestSessionIsScopedToItsOrigin`
covers it.

**The token is hashed as the client sends it, not as the bytes before
encoding.** D2's `stored = sha256(token)` is ambiguous about which. Hashing the
text means the read path can re-hash the header value directly and a
non-base64url value can never collide with a minted one; it also keeps the
mint and the read using one expression. `TestStoredTokenHashIsNotTheToken`
asserts the stored key is the digest of the text.

**Logout runs no CSRF check, and does not need one.** D6 does not say either
way. A cross-origin HTML form can only send `GET` and `POST`, and a
cross-origin `fetch` with `DELETE` needs a preflight, so the request cannot be
forged. The alternative — requiring `X-Aivan-Csrf` on logout — would leave a
browser that lost its token unable to clear its own cookie.

**The session endpoints resolve their own request shape.** D2 says the route is
not reached through `forwardAuth`, so `X-Forwarded-Method` and
`X-Forwarded-Uri` are absent and `forwardedFrom` refuses. `sessionForwarded`
falls back to the request's own method and URI and takes
`X-Forwarded-Proto`/`X-Forwarded-Host` when a proxy supplies them. The mint then
pins the signed method and target to `POST /__aivan/session` rather than
trusting the forwarded values, which is what closes the proof-replay gap above.

**`last_seen_at` is written by the mint's insert, not by a second statement.**
D2 asks for the write "in the same statement as the insert". The statement is
`insert ... select ... from` a CTE that updates the device row, so a device that
was revoked between the proof check and the insert produces no row and the mint
is a refusal: one statement, and the revocation cannot be raced.

**The `p99` latency test fails under `-race` and that is pre-existing.** On the
untouched tree `TestVerifyPercentiles` reports p50=4.75 ms p99=6.06 ms under the
race detector and passes without it. The race detector's overhead, not this
phase, is the cause; the functional tests were run with `-short` under `-race`
and the percentiles were run without it.

## Decisions inside the plan's latitude

- **204 with identity headers, empty body.** D2 allows 204 or a 200 with a JSON
  body. 204 keeps one representation of the identity (the headers Phase E
  reads) and one fewer thing to parse. The headers are the same set a verify
  returns, with `X-Aivan-Proof: session`.
- **`session_invalid` is one reason for expired, idle-timed-out and unknown.**
  One statement cannot tell them apart without a second read, and a client that
  could distinguish them would learn whether a stolen token was ever live.
  Revoked and inactive keep their own reasons because the join knows them and an
  operator needs to see them.
- **`csrf_samesite` is a distinct reason from `csrf_missing`.** They are the
  same status and the same empty body; the decision log is the only place the
  distinction appears, and it is the difference between "the browser said
  something we refuse" and "the client said nothing".
- **The session cookie is built as a whole string, not with `http.SetCookie`.**
  `SetCookie` adds `Expires` and orders attributes its own way; the exact
  attribute set is the contract D7 asserts. The two constants live next to each
  other so a change to one is visible against the other.
- **`internal/console` is its own package.** The revoke transaction needs a
  hook so the crash test can kill the process at the exact midpoint; that hook
  should not be reachable from a request handler. The package runs under the
  same service role as the gate, so a console command holds no privilege a
  request could not.
- **`revoke` reads the device row `for update` before writing.** Two operators
  revoking the same device at once then make one decision about `revoked_at`
  rather than racing on `coalesce`. It also tells an id that matches nothing
  from one that was already revoked.
- **No `X-Aivan-Session` header, ever.** Spec §6.1 and amendment A11: the
  session value is a bearer credential and an application that logs its headers
  would leak it. `TestStoredTokenHashIsNotTheToken` and the existing S8 test
  both assert its absence.

## What this phase does not prove

- **A browser can mint a session.** No enrollment page exists, so the tests and
  the manual run sign with Go's `crypto/ed25519`. Phase F drives the same
  canonical string from WebCrypto; the vectors in
  `internal/proof/testdata/canonical.json` are what both are tested against.
- **The cookie through a real proxy.** Phase A observed that a `Set-Cookie` on
  a forwardAuth response needs `addAuthCookiesToResponse`; this phase avoids the
  question by putting the mint on its own router, and Phase E proves the route
  reaches the gate through Traefik.
- **`Sec-Fetch-Site` from a real browser.** The header's presence and values
  were exercised with `curl` and Go clients. A browser sends `same-origin` for
  a same-origin `fetch` and HTML form, but that exact pairing is Phase E's
  end-to-end check.
- **CORS.** D5's rule depends on no CORS middleware answering a preflight
  permissively. None is configured on the gated router; the middleware manifest
  is Phase E's, and the rule must be revisited if one is added.
- **Session table growth.** Sessions are deleted on logout and on revoke, and
  expired rows are left for Phase G's purge ticker. There is no cap analogous
  to `NonceTableCap`, because a session requires a proof and is bounded by the
  number of devices.
- **S18.** Unchanged from Phase C: Traefik's `maxBodySize` ceiling and the
  one-byte-over test are Phase G.

## Handoff to Phase E

Available and tested: `POST /__aivan/session` minting a `__Host-` cookie from a
proof, `DELETE /__aivan/session` for logout, the cookie read as a second
prepared statement with the same one-round-trip budget, the CSRF rule on unsafe
methods, `authz list-devices` and `authz revoke`, and `gate.ProofSession` as the
`X-Aivan-Proof` value a cookie-authenticated request carries.

For Phase E's dev mint: `POST /__aivan/session` with a dev device's proof is
enough, and the identity comes back on the 204 in the same headers a verify
sets. Two things the cluster test must supply that this phase could not:
`X-Forwarded-Proto: https` and `X-Forwarded-Host: aivan-hud.home.arpa`, because
the mint's route check refuses `http` and an unknown host exactly as verify
does. `revoke` is the way to end a dev session if the cookie outlives the test.
