# Phase G — verification record

Date: 2026-11-13. Cluster: k3s, Traefik 3.7.13, PostgreSQL 14.5 (CloudNativePG,
namespace `aivan-core`), gate and hud in `hermes-agent`. Local: PostgreSQL 18 on
a scratch data directory, Traefik 3.7.13 in a container, k6 v1.3.0.

## What was built

| Plan item | Where |
|---|---|
| G1 purge | `internal/gate/purge.go`, `store.PurgeSQL` and `store.PurgeSessionsSQL`, the startup pass and the ticker in `cmd/authz/main.go` |
| G2 `413` | `maxBody` in the policy file (`internal/config`), `AIVAN_MAX_BODY` in the Deployment, `maxBodySize: 2097152` in the middleware |
| G3 log hygiene | `internal/audit` (`reasons.go`, `log.go`, `sqlstate.go`), `gate.Reason` aliased to it, the handler installed in `newLogger` |
| G4 load | `test/load/verify.js`, `test/load/seed`, `doc/latency-report.md` |
| G5 drills | `test/drill/sign`, results in `doc/runbook.md` §10 |
| G6 runbook | `doc/runbook.md` |
| G7 housekeeping | devtools tag and selftest removed, image pinned by digest, `terminationGracePeriodSeconds: 20` |
| warm pool | `store.Warm`, called before the listener opens |

## Deviations from the phase file

### 1. The phase file's `delete … interval` for sessions needed two rules

G1 gives one statement:

```sql
delete from authz.sessions where idle_expires_at < now() - interval '1 hour'
                              or absolute_expires_at < now();
```

That is what is implemented, but the grace applies to the idle rule only. An
absolutely expired session is removed as soon as it is seen, because it is past
any grace by construction and keeping it serves no race. Both rules are in one
statement, so the transaction still covers both tables.

The nonce rule is the phase file's exactly: one hour past expiry.

### 2. The handler's purge is the ticker's purge

The phase file says "one ticker in `serve`". The nonce handler already ran a
purge before each insert so the table cap holds even with no ticker, which the
tests rely on. Rather than keep two schedules, both now call `Purge`; the handler
runs it when the minute has elapsed, the ticker when its tick fires, and the two
share one `lastRun`. That keeps the handler's cap check working and gives the
ticker one job.

### 3. `413` needed a body that reaches the application

The phase file's first row is "1048575 bytes reaches the application". That can
only be observed with an application that reads the body and reports what it
got, so the drill used a stand-in that echoes `Content-Length` and the byte
count it read:

```console
$ /tmp/sign -target https://aivan-hud.home.arpa:18443 -path /admin \
    -method POST -body-file /tmp/body-1048575.bin -nonce-file /tmp/n413-run.json
attempt 1: 200 OK body="method=POST path=/admin content_length=1048575 read=1048575\n"
```

The body is not truncated: what the application received equals what was sent.

### 4. The proxy ceiling had to move, and the two numbers are now checked

`deploy/routing.yaml` had `maxBodySize: 1048576`, equal to the gate's limit, so
Traefik would have answered first. It is now 2097152. The policy file gained a
`maxBody` key, and `config.Load` refuses to start when it is not above
`AIVAN_MAX_BODY`; the two values live in different files and would otherwise
drift.

Observed on the cluster:

| Body | Result |
|---|---|
| 1048575 | `200`, application read all 1048575 bytes |
| 1048577 | `413` from the gate, `reason: body_too_large` |
| 2097153 | `401` from Traefik, no gate decision |

### 5. `slog` filtering is a handler, and the reason set is a package

G3 asks for both. `internal/audit` holds the closed reason set (with a test that
compares each constant to a hand-written literal) and a `slog.Handler` that
drops any attribute whose key contains a denied segment. `gate.Reason` is now an
alias for `audit.Reason`, so there is one declaration and the gate's existing
names still compile.

Two things this caught:

- The **allow** path carries no reason. Publishing `unknown` for it was wrong and
  showed up immediately in the cluster log; the writer now omits an empty reason
  and still refuses to publish an undeclared non-empty one.
- A pgx error's own message can carry the DSN. `audit.Error` publishes SQLSTATE
  and the server's short message instead, and `audit.Scrub` covers the paths
  that do not go through a pgx error.

The log hygiene test drives a real signature, nonce and cookie through every
route including the failure paths, and asserts none appears in stdout. It fails
when the handler is removed; that was checked by temporarily logging
`nonce`/`signature` at debug and confirming the test failed, then reverting.

### 6. The load profile needed two modes and a seeder

The phase file's snippet sends everything to `/__aivan/verify`. Through Traefik
that path is served by the gate's own router, so the middleware never runs and
the forwarded URI is the verify endpoint rather than the resource the client
signed. The script therefore has two modes: `AIVAN_VIA=handler` posts the
forwarded headers at the handler (the 5 ms claim) and `AIVAN_VIA=traefik`
requests a gated application path and lets the middleware call the gate (the
10 ms claim).

The sustained figure comes from `AIVAN_PROFILE=steady200`, a
`constant-arrival-rate` at 200/s for three minutes. The phase file's ramping
profile is implemented and was run, but it spends most of its life below 200 and
its summary is not the sustained number.

Nonces are pre-generated by `test/load/seed` with COPY, 100k at a time, and the
script consumes one per accepted request. A nonce is single use, so a second run
over the same pool would present spent ones; `-nonce-file` and
`AIVAN_NONCE_OFFSET` exist for that.

### 7. The pool was cold at the first request

The first runs showed connection-pool waits in the first second. pgxpool creates
`MinConns` in the background and dials the rest on demand, so the first requests
raced a dial. `store.Warm` now acquires the whole pool before the listener
opens: a slow database is a start failure rather than a slow first request.
`MaxConns` stays 16.

### 8. `-race` and the latency budget

`TestVerifyPercentiles` asserted p99 under 5 ms. Under `-race` the detector's
overhead is several times the budget, so the test failed for a reason that says
nothing about the shipped binary. It now reports the number under `-race` and
asserts the budget only in a plain build, with a build tag that says which it is.

### 9. NetworkPolicy is in audit mode on this cluster

The database drill first tried to isolate the gate's egress with a
`NetworkPolicy`. The gate kept answering, and `cilium-config` showed
`policy-audit-mode: true`: this cluster's Cilium records policy verdicts without
enforcing them. That is worth knowing for the "reachable only from Traefik"
claim (acceptance 10): the policy is applied and correct, but this cluster does
not enforce it. The drill used a frozen postmaster instead.

## Observed results

### Purge (G1)

`internal/gate/purge_integration_test.go`:

- an expired nonce and an idle-expired session are removed, a live one of each
  survives;
- a session past its absolute cap is removed even when its idle expiry was just
  slid forward;
- renaming `authz.sessions` makes the second statement fail and the first
  statement's delete is rolled back;
- the schedule is 60 s and the grace is one hour.

`cmd/authz/logs_integration_test.go` asserts the startup pass through the real
binary: rows present before `serve` starts are gone by the time `/healthz`
answers.

### Log hygiene (G3)

```console
$ go test -tags integration ./cmd/authz/ -run TestServeLogCarriesNoSecrets -v
--- PASS: TestServeLogCarriesNoSecrets (0.63s)
```

The test sends a valid proof, a replay, a bad signature, a malformed proof, no
proof, a mint, a cookie verify, a logout, the enrollment page, a malformed claim
and an oversized body, then asserts the nonce, both signatures and the cookie
are absent from stdout and that every line is JSON.

### Latency (G4)

Full numbers in `doc/latency-report.md`. At 200 rps sustained:

| Claim | Budget | Observed |
|---|---|---|
| p99 at the gate's handler | 5 ms | **1.99 ms** (p50 1.48, p95 1.67) |
| p99 end to end through Traefik | 10 ms | **7.46 ms** (p50 2.88, p95 5.66) |
| `503`s | none | zero |
| connection-pool waits | none | `acquire_avg_us: 3`, `canceled_acquires: 0` |

### Drills (G5)

All five in `doc/runbook.md` §10. The two that needed care:

- **Kill the gate:** `/admin` `500`, `/` `200`. The `500` is Traefik's, which is
  what Phase A recorded for an unreachable auth service.
- **Stop Postgres:** with every postgres process frozen, `/readyz` `503`,
  `/healthz` `200`, `/admin` `401` (refused), `/` `200`, restart count 0; after
  the resume, `/readyz` `200` without a restart.

Revoke under traffic: 330 requests `200`, then 1670 `401` with
`reason: device_revoked`, no `500`s. Replay: `200` then `401` with
`reason: nonce_unknown`. Clock skew ±10 minutes: `401` with
`reason: timestamp_skewed`.

### Housekeeping (G7)

```console
$ git grep -n 'devtools' -- '*.go' '*.js' '*.html'
$ go vet ./... && go vet -tags integration ./...
$ gofmt -l .
$ go test -race ./...
$ PGHOST=… PGPORT=… PGUSER=… PGDATABASE=… go test -p 1 -race -tags integration ./...
```

All clean. The image is pinned by index digest:

```console
$ docker manifest inspect golang:1.26.5-bookworm
$ docker pull -q gcr.io/distroless/static-debian12:nonroot
$ docker inspect --format '{{index .RepoDigests 0}}' gcr.io/distroless/static-debian12:nonroot
gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
```

`terminationGracePeriodSeconds` is 20, above the 10 s drain. The gate has no
`Ingress` or `IngressRoute` of its own:

```console
$ kubectl -n hermes-agent get ingressroute
NAME               AGE
aivan-hud-gate     6h
aivan-hud-gated    6h
aivan-hud-public   6h
```

All three are bound to `aivan-hud.home.arpa`; none names a host of the gate's
own.

### The selftest, and what replaced it

The devtools selftest compared `canonical.js` with `internal/proof` across the
shared vectors. Removing it left that comparison with no test, so
`TestBrowserCanonicalConstantsMatch` now reads `canonical.js` and asserts the
version line, the code length and the Crockford alphabet against the Go
constants. The full string agreement was demonstrated by the Phase F selftest
and by a real browser enrollment; it is not re-demonstrated per commit.

## Where the phase file was wrong

1. **The session purge needs the idle grace, not a single rule.** Covered above.
2. **`/__aivan/verify` cannot be the load target through Traefik.** The gate's
   own router serves it, so the middleware is bypassed. The script needed the
   two-mode split.
3. **The pool needs warming to make "no pool waits" true.** The phase file lists
   pool size as a thing to check if p99 misses; the actual cause was lazy
   connection creation, and the fix is at startup.
4. **The latency assertion could not hold under `-race`.** Split by build tag.
5. **The runbook's "someone else follows it" is not satisfied.** It was executed
   by its author only. Recorded as an open item in §G9.

## Open items carried forward

From the parent plan §12, restated here because Phase G's exit criteria require
them to be visible:

- **hud's own password login.** It stays for now and is what the rollback in
  `doc/runbook.md` §8 relies on. Whether it survives the gate being permanent is
  an application decision.
- **Exact lifetimes.** The nonce TTL (120 s), skew (300 s), session idle (15 m)
  and absolute cap (8 h) are the design's defaults. No real usage has been
  measured long enough to change them; the purge grace (1 h) is far above any of
  them and does not interact.
- **Registration policy** for people other than the first admin. Spec §10 defers
  it; `pending_enrollments` is the mechanism, and `enroll-new` is the only way a
  record is created.

And one this phase found:

- **NetworkPolicy is not enforced on this cluster** (`policy-audit-mode: true`).
  Acceptance 10 holds by configuration; enforcing it needs a CNI change, which is
  outside this service.

## What comes after

Unchanged from the phase file: grants (spec §6.3), mTLS, phone push, a sign-in
page for an already-enrolled device, and multi-replica readiness. The sign-in
page is the one a user notices first: today, losing the cookie means
revoke-and-remint rather than signing in again with the key still on disk.

## Requirement to evidence map

Phase G's exit criteria ask that every requirement S1–S21 has a test or a written
reason it does not. This is that map; the earlier phases' records hold the
detail.

| # | Where it is proved |
|---|---|
| S1 replay refused | `TestS1ReplayIsRefused`; observed on the cluster (`doc/runbook.md` §10) |
| S2 every covered field matters | `TestEveryCoveredFieldMatters` |
| S3 expired nonce refused | `TestS3ExpiredNonceIsRefused` |
| S4 clock skew refused | `TestS4SkewWindow`, `TestS4TimestampBeforeNonceIssuance`; observed with `test/drill/sign -skew ±10m` |
| S5 revoke, and its sessions | `TestS5RevokeKillsTheLiveSession`; observed under load (`doc/runbook.md` §10) |
| S6 client header cannot reach the app | Traefik's `authResponseHeadersRegex`, recorded in `doc/traefik-contract.md`, and acceptance 4 against the cluster in `doc/phase-e-record.md`. The gate's half is S8: it never reads an identity header. |
| S7 role required | `TestS7UserWithoutGroupsIsRefusedOnAdmin`, `TestS7AdminRoleAdmits` |
| S8 identity cannot be spoofed | `TestS8IdentityCannotBeSpoofedByHeaders` |
| S9 unknown code refused | `TestS9ClaimWithAnUnknownCodeIsRefused` |
| S10 mismatched code refused | `TestS10SignatureOverADifferentCodeIsRefused`, `TestS10CapturedClaimWithASwappedKeyIsRefused` |
| S11 user comes from the record | `TestS11DeviceUserComesFromTheRecord` |
| S12 | Withdrawn in revision 2 (no password path). |
| S13 CSRF | `TestS13CSRF` |
| S14 denials indistinguishable | `TestS14AllDenialsAreIdentical`, `TestS14DenialPathsCostTheSame` |
| S15 constant-time comparison | No test asserts timing. The reason is written in `internal/gate/gate.go` and `doc/phase-c-record.md`: the service compares no secret in Go. The nonce and the session token are primary-key equality on fixed-size digests inside PostgreSQL, and signature verification is library code. |
| S16 refuses a too-powerful credential | `TestPrivilegeProbeRefusesSuperuser`, `TestServeRefusesSuperuser` |
| S17 algorithm from the row, not the request | `TestS17AlgorithmNotOnTheListIsRefused` |
| S18 body limit, not truncation | `TestS18BodyAtTheLimitIsVerifiedWhole`, `TestS18BodyOverTheLimitIs413`, `TestS18BodyOverTheLimitOnEveryMethod`, `TestBodyLimitComesFromConfig`; the three-row matrix on the cluster in `doc/runbook.md` §9 |
| S19 query string is covered | `TestQueryStringIsCovered` |
| S20 cannot read password_digest | `TestPrivilegeProbeRefusesPasswordDigest`, `TestServeRefusesPasswordDigest` |
| S21 origin binding | `TestS21DeviceIsBoundToItsOrigin`; the two-host deployment was Phase E |
