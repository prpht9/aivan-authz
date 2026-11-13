# Phase C — verification record

Date: 2026-11-13. Recorded so Phase D does not have to re-derive it.

## What was built

| Plan item | Where |
|---|---|
| C1 canonical string | `internal/proof/canonical.go`, `testdata/canonical.json` |
| C2 algorithms | `internal/proof/verify.go` |
| C3 nonce issuance | `internal/gate/nonce.go` |
| C4 verify statement | `internal/store/queries.go` (`VerifySQL`), `internal/gate/verify.go` |
| C5 policy | `internal/policy/policy.go` |
| C6 denials | `internal/gate/verify.go` (`deny401`, `refuse`), `internal/gate/gate.go` |
| C7 body handling | `internal/gate/verify.go` (`bodyDigest`) |
| C8 tests | `internal/proof/*_test.go`, `internal/policy/*_test.go`, `internal/gate/*_test.go` |
| C9 benchmark | `internal/gate/bench_integration_test.go` |
| pool instrumentation | `internal/store/instrument.go` |
| request id, shared | `internal/reqid/reqid.go` |

Files changed outside the new packages: `cmd/authz/main.go` (pool options, gate
construction, maintenance goroutine), `internal/config/config.go` (now returns
`*policy.Table`), `internal/httpx/router.go` (mounts the two endpoints),
`internal/httpx/middleware.go` (request id moved to `internal/reqid`),
`test/harness/harness.go` (helpers take `testing.TB` so a benchmark can use
them), `deploy/k8s.yaml` (trusted proxy CIDR).

## Checklist, with what was observed

Checked on a throwaway PostgreSQL 18.6 cluster (`initdb` in `/tmp`, port
55432), Go 1.26.5, this machine.

- [x] All three canonical vectors produce `expected` byte for byte, and the file's
      body hashes were verified against `sha256sum` rather than trusted.
- [x] Changing any covered field changes the string. Table-driven over method,
      scheme, host, target, body hash, nonce and timestamp. S2, S19.
- [x] `alg_unsupported` for `rs256`, `none`, `ES256`, `Ed25519`, `ecdsa`, `""`,
      `es512`, `ed448`. S17.
- [x] ES256 refuses a raw `r||s` signature, a DER pair with a trailing byte, and
      any signature from the wrong key. DER is the only accepted encoding.
- [x] Policy: longest prefix wins, equal length refused at startup, an uncovered
      prefix defaults to `authenticated` with `Defaulted` set, and a `/api`
      prefix does not match `/apifoo`.
- [x] A second use of a consumed nonce is refused, and the nonce row is gone
      afterwards. S1.
- [x] A nonce past `expires_at` is refused (injected clock). S3.
- [x] Timestamps at −300 s and +300 s are accepted; −301 s and +301 s are
      refused. A timestamp 90 s before `issued_at` is refused while inside the
      skew window. S4.
- [x] A device bound to `second.home.arpa` is refused when presented to
      `aivan-hud.home.arpa`, and still works on its own host. S21.
- [x] A revoked device is refused. S5 device half.
- [x] A user with no groups is 403 on `/admin` and 200 on `/dashboard`. S7.
- [x] A device of alice presenting `X-Aivan-User: bob`, `X-Aivan-User-Id: 2`,
      `X-Aivan-Roles: admin`, `X-Aivan-Session` and `X-Aivan-Proof: session` is
      still alice with `admin,free`, and no `X-Aivan-Session` is returned. S8.
- [x] Eleven 401 cases produce byte-identical status, body and headers, with the
      per-request id the only difference. S14.
- [x] Exactly one statement per successful verify; zero for a request rejected
      before the database. Asserted on the pool counter.
- [x] `/__aivan/verify` answers GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE and
      PROPFIND with no panic, both in `httptest` and against the real binary.
- [x] `go test -bench . -benchtime 20s` reports
      `BenchmarkVerify/verify-12  19765  1204649 ns/op  14216 B/op  177 allocs/op`
      and `BenchmarkVerify/nonce-12  29138  738334 ns/op`.
      `TestVerifyPercentiles` reports p50 1.18 ms, p99 1.64 ms, max 2.64 ms over
      2000 requests. Exit target is p99 under 5 ms.
- [x] Every security test above was shown to fail when its guard was removed.
      Table below.
- [x] Race detector clean over the security tests.

## Guard removal, one at a time

Each row is a temporary edit, the test it broke, and what was deleted. The
script that did it is not committed; the tree was restored after each run.

| Requirement | Guard temporarily removed | Test that failed |
|---|---|---|
| S1 | `delete from authz.nonces` became `select` in `VerifySQL` | `TestS1ReplayIsRefused` |
| S2, S19 | the `Target` line in `Canonical` | `TestEveryCoveredFieldMatters`, `TestQueryStringIsCovered`, `TestCanonicalVectors` |
| S3 | `and expires_at > now()` in `VerifySQL` | `TestS3ExpiredNonceIsRefused` |
| S4 | the skew comparison in `verify.go` | `TestS4SkewWindow` |
| S4 | `timestamp < row.issuedAt` compared to `issuedAt` | `TestS4TimestampBeforeNonceIssuance` |
| S5 | `case row.revokedAt != nil` | `TestRevokedDeviceIsRefused` |
| S7 | the `admin` role check in `CheckClass` | `TestS7UserWithoutGroupsIsRefusedOnAdmin` |
| S8 | `row.username = r.Header.Get(HeaderUser)` before the identity | `TestS8IdentityCannotBeSpoofedByHeaders` |
| S14 | the constant `denialBody` replaced by `"denied: "+reason` | `TestS14AllDenialsAreIdentical` |
| S17 | `if false && !proof.Supported(...)` | `TestS17AlgorithmNotOnTheListIsRefused` |
| S21 | `case row.origin != f.Host` | `TestS21DeviceIsBoundToItsOrigin` |
| one statement | a second `select count(*) from public.groups` before the headers | `TestCounterIsWired`, `TestValidProofIsAllowed` |

## Findings that changed the plan's assumptions

**The verify statement needs `d.kind`.** The plan's §5.4 statement selects
`d.id, d.public_key, d.alg, d.revoked_at, d.user_id, d.origin, u.username,
u.active, c.issued_at, roles`. `X-Aivan-Device-Kind` is part of the output
contract (§6.1), and the plan's statement has nothing to fill it from. Adding
`d.kind` to the select and the group-by is the smallest change; a second query
for it would break the one-round-trip budget the same phase asserts.

**S17 is partly enforced by the schema, so the handler test needed a reason
assertion.** `authz.devices.alg` has `check (alg in ('ed25519','es256'))`, so a
row with `alg = 'rs256'` cannot exist in a correct database. Removing the
handler's `proof.Supported` check left the 401 in place, because
`proof.Verify`'s default branch refuses an unknown algorithm too — the test
passed with the guard gone. The requirement is not only "refused" but "log
`reason=alg_unsupported`", so the test now asserts the decision log's reason,
and removing the guard fails it. The test drops the check constraint to create
the row, which also documents that the schema is the first of two lines.

**The `X-Forwarded-Host` the device signs can carry a port.** `X-Forwarded-Host`
is whatever the client sent. `NormalizeHost` lowercases it and strips a port,
and the browser must strip `location.port` the same way. The test vectors use a
host without a port; Phase F's browser test needs a case with one.

**A denial that finds no nonce row is faster unless the work is equalised.**
Measured: 708 µs p50 for "a real device with a consumed nonce" against 469 µs
for "no nonce row", a 1.5x gap, and the no-row path covers a device id with no
row. The no-row path now runs a full verification against a fixed real keypair
before writing the 401, which brought the gap to within run-to-run noise. The
timing test reports the numbers and does not fail on them; a wall-clock
assertion on a shared machine is flaky and the guarantee is structural.

**A request that exceeds `MaxRequestTime` gets a 503 with a body, so not every
503 is empty.** Observed: `timeoutMiddleware` writes status `503` and
`request timeout\n`. The gate's own database 503 has an empty body (C6). Both
are 503, so a client treats them the same, and neither leaks anything, but an
operator reading bodies will see two shapes. That is accepted rather than
fixed: the timeout is `httpx`'s wrapper and the alternative is to teach it the
gate's body rules, which couples a generic middleware to one handler's
contract. No test approaches `MaxRequestTime`, so the path is unexercised in
practice today.

## Decisions inside the plan's latitude

- **`internal/gate` is a separate package from `internal/httpx`.** The decision
  logic is testable without a listener, and `NewRouter(pool, log)` keeps its
  Phase B signature (health only) so the existing tests and call sites did not
  change. `NewRouterWith` mounts the gate.
- **`internal/policy` is a prefix table, not a rules engine.** Routes are sorted
  longest-first at construction, so a match is one linear scan and the
  precedence is fixed before any request arrives. A prefix matches whole path
  segments: `/api` governs `/api` and `/api/x`, never `/apifoo`.
- **The nonce endpoint's maintenance is one lock and a minute stamp.** Purge and
  count run on the same once-a-minute schedule, before an insert, so a stale
  table cannot grow past the cap while the ticker has not fired. `RunMaintenance`
  drives it from a ticker as well so a quiet service still purges. Phase G
  replaces this with the purge ticker that also covers sessions.
- **Rate limiter is a token bucket per source address**, 30/minute with a burst
  of 10, holding its mutex only for arithmetic. It sweeps buckets idle for more
  than a minute, because a map keyed on client-controlled addresses is a leak an
  attacker would otherwise drive.
- **The 413 is written by the gate, not by `MaxBytesReader`.** `MaxBytesReader`
  marks the response but the gate writes the status and the empty body itself,
  so the 413 has the same shape as every other refusal.
- **`deploy/k8s.yaml` names `192.168.196.0/24` as the trusted proxy CIDR.** That
  is the node's observed `podCIDR` on this cluster. If the cluster is rebuilt,
  the environment variable must be re-checked, because a wrong CIDR means one
  client's nonce traffic is charged to Traefik's pod.
- **The counter counts `Query`, `QueryRow` and `Exec` through pgx's tracer.**
  `Prepare`, pool setup and transaction control are not statements, so the
  number is the round trips a request costs, which is what the budget is about.
- **Prepared statements are named and prepared in `AfterConnect`.** Every
  connection the pool ever hands out has all four, so no request pays a
  `Describe` round trip on a cold connection.

## What this phase does not prove

- **A browser can produce a valid signature.** No enrollment page exists yet
  (Phase F). The tests sign with Go's `crypto/ed25519`; the ES256 path is tested
  with a Go-generated P-256 key and ASN.1 signatures, which is the encoding
  WebCrypto emits, but the round trip through a real browser has not happened.
- **S6.** That a client-supplied `X-Aivan-*` header cannot reach the application
  is Traefik's `authResponseHeadersRegex`, already recorded in
  `doc/traefik-contract.md`. The gate contributes by never reading an identity
  header, which S8 tests, but the end-to-end strip is Phase E against the cluster.
- **S15 as a claim about the stored-token comparison.** There is no session token
  yet. The service compares no secret material in Go: the nonce comparison is a
  primary-key equality inside PostgreSQL and signature verification is library
  code. The session half is Phase D.
- **S18.** A body over `AIVAN_MAX_BODY` is refused with `413` (tested), but
  Traefik's `maxBodySize` ceiling above it and the one-byte-over test are Phase G.
- **S21 against the cluster.** The gate refuses a foreign origin (tested against
  two configured hosts), but the two-host deployment is Phase E.
- **`last_seen_at`.** Not written, per the plan. An operator cannot yet answer
  "when was this device last used".

## Handoff to Phase D

Available and tested: `gate.Gate` with `Verify` and `Nonce` as handlers;
`deny401` / `refuse` writing the one denial shape; `decisionLogger` writing
`decision` lines with a reason code; `store.Counter` and
`store.WithStatements`; `policy.Table.Match` returning a class and whether it
defaulted; `proof.Canonical`, `proof.Verify`, and `testdata/canonical.json` as
the one definition the browser will also be tested against; and
`reqid.WithRequestID`.

Phase D needs to add `POST`/`DELETE /__aivan/session`, the cookie, the sessions
read path as a second prepared statement of the same shape, the CSRF rule, and
the session half of S5. The denial helpers and the counter are the parts it
should reuse rather than re-implement.
