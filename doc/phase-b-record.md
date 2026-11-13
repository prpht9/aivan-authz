# Phase B — verification record

Date: 2026-11-13. Recorded so Phase C does not have to re-derive it.

## What was built

| Plan item | Where |
|---|---|
| B1 scaffold | `.mise.toml` (go 1.26.5), `Makefile`, `go.mod` |
| B2 configuration | `internal/config/config.go`, `config_test.go` |
| B3 schema | `internal/store/schema/0001_init.sql`, `0002_grants.sql`, `migrate.go` |
| B4 privilege probe | `internal/store/probe.go`, `probe_integration_test.go` |
| B5 health | `internal/httpx/health.go`, `health_test.go`, `health_integration_test.go` |
| B6 server | `cmd/authz/main.go`, `internal/httpx/router.go`, `middleware.go` |
| B7 container | `deploy/Dockerfile`, `deploy/k8s.yaml` |
| test harness | `test/harness/harness.go`, `test/fixtures/hud_min.sql` |

## Checklist, with what was observed

Checked on a throwaway PostgreSQL 18.6 cluster (`initdb` in `/tmp`, port
55432), because this machine's main cluster asks for a password on TCP and the
harness needs to create roles and databases.

- [x] `make build` produces `bin/authz` (15.9 MB, stripped by the image build
      but not by `make build`, which keeps symbols for debugging).
- [x] `authz migrate` against a fresh database creates `authz.*` and records two
      versions: `{"msg":"migrations applied","versions":[1,2]}`. A second run
      prints `{"msg":"migrations up to date"}` and exits 0.
- [x] `authz serve` with the correct role starts and logs one line:
      `{"level":"INFO","msg":"listening","listen":"[::]:18080","hosts":1,"policy":"/tmp/aivz-policy.yaml"}`.
- [x] `authz serve` with a superuser DSN exits 1 with:
      `refusing to start: database role can create objects in schema public.`
- [x] `authz serve` with a DSN that can read `password_digest` exits 1 with:
      `refusing to start: database role can read public.users.password_digest.`
- [x] Each config refusal has a test, and each test fails when its guard is
      removed. Thirteen guards were removed one at a time (`/tmp` script, not
      committed); every corresponding test failed. The cases are the rows of
      `TestRefusals` plus the CIDR parse.
- [x] `/readyz` returns `503` within two seconds of Postgres stopping, and `200`
      after it returns, without restarting the pod. Observed: `503` in 1.1 ms
      with body `database unreachable`, `200` in 12 ms after restart, same PID
      throughout. `/healthz` returned `200` in 0.4 ms while the database was
      down.
- [x] `/healthz` returns `200` while Postgres is down.
- [x] Image is 14.2 MB, and the container's process runs as uid 165531
      (`nonroot`) with `CapEff: 0000000000000000`. Verified with `docker run`
      and `/proc/<pid>/status`; `kubectl exec ... id` was not run because the
      manifest has not been applied to the cluster yet (the database secret is
      a placeholder).
- [x] First commit on `master`.

## Two findings that changed the plan's assumptions

**0001 has the same dependency as 0002.** The plan says only `0002_grants.sql`
needs `public.users` and `public.groups`, because of the column-level grants.
In fact `0001_init.sql` also needs `public.users`: `authz.devices`,
`authz.sessions` and `authz.pending_enrollments` all carry
`references public.users(id)`. A migration on a database without the
application schema fails at `0001`, not at `0002`. The failure is legible
(`migration 0001_init.sql: ERROR: relation "public.users" does not exist`) and
the transaction rolls back, so the database is left clean rather than
half-migrated. This is recorded in `TestMigrateWithoutApplicationSchema` and in
a comment on `0001`.

**The probe needs savepoints.** The two assertions that pass by being *denied*
are errors, and PostgreSQL aborts a transaction on the first error. A probe
written as three plain statements would report the second assertion as
`25P02 current transaction is aborted` instead of a denial. Each assertion now
runs inside a savepoint and is rolled back to, so the passing outcome does not
poison the next check. Without this, a correctly configured role would be
refused at startup — the failure mode the integration test caught first.

## Decisions inside the plan's latitude

- `serve` keeps symbols (`make build`); the image build strips them. Two
  different concerns, two different flags.
- `max_conns = 16`, `min_conns = 2`, `application_name = aivan-authz`.
- `/readyz` reads `select 1 from authz.devices limit 1` and treats **no rows** as
  success. An empty `devices` table is a readable table.
- Readiness reasons are four fixed strings, so the endpoint never leaks a DSN or
  a schema name.
- The router mounts `/healthz` and `/readyz` only. Phase C adds
  `/__aivan/verify` and `/__aivan/nonce` to the same mux.
- `AIVAN_TRUSTED_PROXY_CIDRS` is parsed and validated now, unused until Phase C
  (it is the rate limiter's input).
- The `k8s.yaml` NetworkPolicy admits Traefik in `kube-system`
  (`app.kubernetes.io/name: traefik`, verified on the live cluster) and allows
  egress to `aivan-core` on 5432 plus DNS only.
- `deploy/k8s.yaml` has a placeholder database secret. The real DSN is created
  out of band; the file says so rather than inventing a value.

## What this phase does not prove

- Nothing about authentication. There is no `/__aivan/verify` yet.
- The k8s manifest has been validated with `kubectl apply --dry-run=client`
  only. It has not been applied, so the probes have not been observed under
  kubelet, and the NetworkPolicy has not been observed enforcing anything.
- The image was run with `docker run` against the throwaway cluster, not as a
  pod against `aivan-core`.

## Handoff to Phase C

Available: `config.Config` (validated, with `Hosts`, `Skew`, `NonceTTL`,
`SessionIdle`, `SessionMax`, `MaxBody`, `TrustedProxies`, `Policy`),
`store.DB` with a `pgxpool` of 16 connections, the `authz` schema applied,
`httpx.NewRouter` as the place to mount the two Phase C handlers,
`httpx.RequestIDFrom` / `RequestIDHeader` for the request id, and
`test/harness.Setup` for a database with the fixture and migrations applied.

Not available, by design: a prepared-statement helper and the query counter.
Phase C adds both, because that is where the one-round-trip budget first
matters.