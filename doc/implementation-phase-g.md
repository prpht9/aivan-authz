# Phase G — hardening and operations

Status: complete (2026-11-13). Record: `doc/phase-g-record.md`.

Standalone work file. Prerequisites: Phase F complete (a browser enrolls and
reaches a protected route). No other phase file needed.

Parent plan: `doc/aivan-initial-plan.md` §8 Phase G, §11. Spec:
`doc/aivan-initial-spec.md` §8.2, §8.3, §9 (S18), §11 (acceptance 5–9).

**Goal:** the gate is fit to leave running unattended. Tables do not grow
without bound, logs carry no secrets, the latency budget is demonstrated under
load, its failure mode is observed rather than assumed, and an operator who
did not build it can follow the runbook.

Everything here is a finishing pass over code that already works. Nothing in
this phase adds a feature.

## G1. Purge

One ticker in `serve`, every 60 s, one statement each:

```sql
delete from authz.nonces   where expires_at < now() - interval '1 hour';
delete from authz.sessions where idle_expires_at < now() - interval '1 hour'
                              or absolute_expires_at < now();
```

- Run them in one transaction so a failure is all-or-nothing and the log line
  names both counts.
- Log the row counts at `debug`. A purge that silently deletes 900k rows is a
  symptom, not a success; `info` if either count exceeds 10000.
- First run at startup, so a restarted gate cleans up before serving.
- The 1-hour grace on nonces exists so a row is never deleted while a request
  could still be racing its `delete … returning`. An expired nonce is already
  refused by the predicate; the grace is about the race, not about validity.
- A `nonce` cap already exists as a `503` from Phase C. Keep it; it is the
  backstop if the ticker stops.

Test: insert an expired nonce and an expired session, run one tick, assert both
are gone and a live one is not. Assert the transaction by making the second
statement fail and confirming the first is rolled back.

## G2. `413`, definitively (S18)

Phase C wired `http.MaxBytesReader`. This phase proves the whole path.

- Gate limit: `AIVAN_MAX_BODY`, default 1048576.
- Traefik's `maxBodySize` must be **above** it, e.g. 2097152, so the gate is the
  one that answers. If Traefik's is lower, a valid-sized-for-us request gets a
  Traefik-authored `401` and the operator learns nothing.
- Add a startup check: if the policy file declares a `maxBody` lower than
  `AIVAN_MAX_BODY`, refuse to start. The two values are in different places and
  will drift otherwise.

Test matrix, against the cluster:

| Body | Expect |
|---|---|
| 1048575 bytes | reaches the application |
| 1048577 bytes | `413` from the gate, application never sees it |
| 2097153 bytes | `401` from Traefik, because the ceiling is exceeded first |

The last row is deliberately a documented limitation. Confirm the number and
write it in the runbook.

Also confirm the body is not truncated: the application's received
`Content-Length` for the 1048575 case equals what was sent.

## G3. Log hygiene

Every log line is JSON on stdout. Nothing below may ever appear:

- signature, nonce, cookie value, `Authorization`, session token, public key
  bytes, the DSN, or a password.

Mechanism, not vigilance:

- Reason codes are constants from a closed set. Enumerate them in
  `internal/audit/reasons.go` with a test that walks the set and asserts each is
  a literal, so a future change cannot interpolate a header into one.
- Log the device id, user id, host, method, route and request id. Never a
  header map.
- The `slog.Handler` is wrapped in a filter that drops any attribute whose key
  is in a deny list (`cookie`, `nonce`, `signature`, `dsn`, `password`), so a
  careless `slog.Info("x", "cookie", v)` in future code is dropped rather than
  published.
- Never log the raw error from pgx when it might embed the DSN; log
  `SQLSTATE` and a short message.

Test: drive a request that carries a signature, a nonce and a cookie through
every route including the failure paths, capture all stdout, and assert none of
the three values appears as a substring. This is the test that makes the
requirement real.

## G4. Latency under load

k6 profile, mixed traffic. Keep the file in `test/load/verify.js` and the report
in `doc/latency-report.md`.

```js
import http from 'k6/http';
// 70% accept with a pre-generated nonce pool, 20% replay (expect 401),
// 10% no proof (expect 401).
export const options = {
  scenarios: {
    steady: {
      executor: 'ramping-arrival-rate',
      startRate: 50, timeUnit: '1s',
      preAllocatedVUs: 100, maxVUs: 500,
      stages: [
        { target: 50,  duration: '1m' },
        { target: 200, duration: '2m' },
        { target: 200, duration: '3m' },
        { target: 0,   duration: '30s' },
      ],
    },
  },
};
```

A nonce must be generated per accepted request, and the pool must be pre-filled
or the load generator measures its own nonce endpoint. Pre-generate 100k nonces
in the database directly for the accept path, which isolates the decision path
from the issuance path.

Acceptance 9 is met when, at 200 rps sustained:

- p99 decision latency is under 5 ms at the gate's own handler, and
- p99 end-to-end through Traefik is under 10 ms, and
- there are no `503`s and no connection-pool waits.

Record p50/p95/p99 and the pool settings. If p99 misses, check in this order:
pool size versus VUs, whether the prepared statement is actually reused, and
whether `array_agg` is spilling to disk with many groups.

## G5. Failure drills

Each one is run once, recorded, and added to the runbook with the observed
behaviour.

**Kill the gate.**

```bash
kubectl -n aivan scale deploy aivan-authz --replicas=0
curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/
kubectl -n aivan scale deploy aivan-authz --replicas=1
```

Expect: `/admin` refused (whatever Phase A recorded), `/` still `200`. That is
spec §8.2 and it must be observed, not inferred.

**Stop Postgres.**

Expect `/readyz` red within one probe interval, `/healthz` green, the pod not
restarting, and protected routes refused. Then start Postgres and confirm
`/readyz` green without a restart.

**Revoke during traffic.** With k6 running, `authz revoke --device <id>`. Expect
every in-flight session for that device to start failing within one request, and
no `500`s. S5 under load, not in a unit test.

**Clock skew.** Move the client clock forward 10 minutes and send a signed
request. Expect `401` with the constant body. This is S4 against a real client,
and it is the failure a user will actually hit.

**Replay.** Capture a signed request with `tcpdump` or DevTools, send it twice.
Expect `200` then `401`. Acceptance 5, observed.

## G6. Runbook

`doc/runbook.md`, written for someone who has not read the plan. It must contain,
with commands that were actually run:

1. Bootstrap, in order: `admin:create` in hud, then `enroll-new` in the gate.
   Note that the first requires a typed password and the second prints a code
   once.
2. Add a device: mint a code, open the gated host, paste it. What the operator
   sees when the person already has a device of that kind.
3. Revoke a device, and what happens to open tabs.
4. Lost phone: current procedure is revoke, then mint a new code. State plainly
   that the phone's key is gone and cannot be recovered.
5. Rotate the database credential: create a new role with the `0002` grants,
   update the secret, restart. Include the privilege-probe refusal message, so
   an operator recognises it as config and not as a bug.
6. What a `401`, `403`, `413`, `429` and `503` mean, and which reason codes
   point at a misconfiguration rather than an attack.
7. Where the decision logs are and the three queries worth running:
   denials by reason, enrollments in the last day, devices not seen in 30 days.
8. Rollback of the whole gate: delete the gated `IngressRoute`, restore hud's
   `Ingress`, confirm `/admin` works on hud's own cookie.

Acceptance for this section: someone else follows it end to end on a clean
install and reports the steps that were wrong. Fix those steps.

## G7. Housekeeping

- Remove `GET /__aivan/selftest` and the `devtools` build tag entirely.
  `git grep -n 'devtools'` returns nothing.
- `go vet`, `gofmt -l` clean, `go test -race ./...` green.
- Pin the base image by digest in `deploy/Dockerfile`, not just by tag.
- Set `terminationGracePeriodSeconds: 20` so the 10 s drain fits.
- Confirm the `NetworkPolicy` still admits only Traefik and that the gate has no
  `Ingress` or `IngressRoute` on any host.
- `doc/implementation-phase-*.md` files stay; they are the record of how the
  service was built. Mark each `Status: complete` with the date.

## G8. Checklist

- [x] Purge runs at startup and every 60 s, transactional, with a test that
      proves the rollback.
- [x] `413` from the gate, `401` above the ceiling, both observed and in the
      runbook.
- [x] Startup refuses a policy `maxBody` below `AIVAN_MAX_BODY`.
- [x] Log hygiene test passes across every route.
- [x] k6 report has p50/p95/p99 at 200 rps and all three latency claims.
- [x] All five failure drills observed and recorded.
- [ ] Runbook followed by someone else, corrections applied. **Not done:** it was
      executed by its author only. Carried into §G9.
- [x] `devtools` and `selftest` gone.
- [x] Acceptance 5, 6, 7, 8, 9, 10 all demonstrated with pasted output
      (`doc/phase-g-record.md`, `doc/latency-report.md`).
- [ ] Tag the release. **Not done:** tagging is the operator's call.

## G9. Exit criteria

- [x] Acceptance 5–10 hold.
- [x] Every requirement S1–S21 either has a test or a written reason it does not
      (S12 is withdrawn; S21 needs two hosts).
- [ ] `doc/runbook.md` exists and has been executed by someone other than its
      author. **Half done:** it exists and was executed by its author.
- [x] The three open items in the parent plan are restated in an issue or a
      note: hud's own password login, exact lifetimes after real use, and
      registration policy (`doc/phase-g-record.md`, "Open items").

## What comes after

Grants (spec §6.3), mTLS, phone push, a sign-in page for an already-enrolled
device, and multi-replica readiness. None block the acceptance criteria. The
sign-in page is the one a user will notice first: today, losing the cookie means
revoke-and-remint rather than signing in again with the key still on disk.