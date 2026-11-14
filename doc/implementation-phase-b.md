# Phase B — skeleton, schema, privileges, health

Status: complete (2026-11-13).

Standalone work file. Prerequisites: Phase A complete (`doc/traefik-contract.md`
exists). You do not need to re-read any other phase file.

Parent plan: `doc/aivan-initial-plan.md` §3, §4, §6, §8 Phase B. Spec:
`doc/aivan-initial-spec.md` §7, §8.4, §9 (S16, S20).

**Goal:** a binary that starts under the correct database role, refuses to start
under a too-powerful one, reports health honestly, and ships as a distroless
image. No authentication logic in this phase.

## B1. Project scaffold

```bash
mise use go@1.26.5           # writes .mise.toml
go mod init github.com/chris/aivan-authz
```

Layout created in this phase (the rest comes later; do not create empty dirs):

```text
aivan-authz/
  .mise.toml
  Makefile
  go.mod
  cmd/authz/main.go
  internal/config/config.go
  internal/config/config_test.go
  internal/store/store.go
  internal/store/migrate.go
  internal/store/schema/0001_init.sql
  internal/store/schema/0002_grants.sql
  internal/httpx/health.go
  internal/httpx/router.go
  deploy/Dockerfile
  deploy/k8s.yaml
```

`Makefile`:

```make
GO ?= go
IMAGE ?= docker.home.arpa:5000/aivan-authz:latest

.PHONY: build test testdb lint image
build:   ; $(GO) build -trimpath -o bin/authz ./cmd/authz
test:    ; $(GO) test ./...
testdb:  ; AIVAN_TEST_DB_URL=$${AIVAN_TEST_DB_URL:-postgres://aivan_authz@localhost/aivan_authz_test} $(GO) test -tags integration ./...
lint:    ; $(GO) vet ./... && test -z "$$(gofmt -l .)"
image:   ; docker build -f deploy/Dockerfile -t $(IMAGE) .
```

## B2. Configuration

Environment only. Every refusal below must have a test.

| Variable | Default | Rule |
|---|---|---|
| `AIVAN_DB_URL` | — | required |
| `AIVAN_LISTEN` | `:8080` | |
| `AIVAN_HOSTS` | — | required; comma-separated; no `*` |
| `AIVAN_POLICY` | `/etc/aivan/policy.yaml` | must exist and parse |
| `AIVAN_NONCE_TTL` | `120s` | must be ≤ `AIVAN_SKEW` |
| `AIVAN_SKEW` | `300s` | |
| `AIVAN_SESSION_IDLE` | `15m` | must be < `AIVAN_SESSION_MAX` |
| `AIVAN_SESSION_MAX` | `8h` | |
| `AIVAN_MAX_BODY` | `1048576` | must be ≥ 65536 |
| `AIVAN_TRUSTED_PROXY_CIDRS` | — | optional; for the rate limiter later |

Refuse to start when: `AIVAN_DB_URL` is empty; `AIVAN_HOSTS` is empty or
contains `*`; a policy host is not listed in `AIVAN_HOSTS`; a policy host is
reached over a scheme other than `https`; `AIVAN_NONCE_TTL` exceeds
`AIVAN_SKEW`; session idle exceeds session max; `AIVAN_MAX_BODY` is below the
floor.

The policy file is read in this phase so that the parse errors exist before
anything depends on them:

```yaml
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin, class: admin }
      - { prefix: /,      class: authenticated }
```

Classes in this phase: `public`, `authenticated`, `admin`. `enrollment` is added
in Phase F. An unknown class is a startup refusal.

## B3. Schema

`internal/store/schema/0001_init.sql` — the full DDL from
`doc/aivan-initial-plan.md` §4, unchanged, with `create schema authz` first.
Copy it; do not retype it.

`internal/store/schema/0002_grants.sql`:

```sql
-- Role creation is the install step's job, not this migration's.
grant usage on schema authz to aivan_authz;
grant select, insert, update, delete on all tables in schema authz to aivan_authz;
grant usage on sequence authz.audit_log_id_seq to aivan_authz;
grant usage on schema public to aivan_authz;
grant select (id, username, active) on public.users  to aivan_authz;
grant select (id, name)             on public.groups to aivan_authz;
grant select                        on public.groups_users to aivan_authz;
revoke create on schema public from aivan_authz;
```

Note: `grant select (cols)` requires the columns to exist. `public.users` and
`public.groups` belong to aivan-hud, so this migration depends on hud's schema
being present. Record that on the migration: a gateway deployed before the
application cannot apply `0002`. Phase E is the first time both exist together,
which is why the local test database in this phase fakes the minimum:

```sql
-- test/fixtures/hud_min.sql, applied only by the integration harness
create table if not exists public.users (
  id bigint primary key, email text, username text, active boolean default true,
  password_digest text
);
create table if not exists public.groups (id bigint primary key, name text);
create table if not exists public.groups_users (group_id bigint, user_id bigint);
```

The fixture deliberately includes `password_digest` so the privilege probe has
something real to be refused.

Correction found while implementing: `0001_init.sql` carries the same
dependency. `authz.devices`, `authz.sessions` and `authz.pending_enrollments`
all declare `references public.users(id)`, so a migrate run against a database
without the application schema fails at `0001`, not at `0002`. The transaction
rolls back, so nothing is half-applied. Recorded in `doc/phase-b-record.md` and
in a comment on the migration.

`internal/store/migrate.go`:

- Reads embedded SQL, sorts by filename, applies each once inside a
  transaction, records the version in `authz.schema_migrations`.
- Takes an advisory lock (`pg_advisory_lock`) so two runs cannot interleave.
- Exposes `authz migrate` as a subcommand; exit code 1 on any failure.

## B4. Privilege probe (S16, S20)

Run at startup, before the listener opens, in one transaction that is rolled
back. Fail closed: if the probe errors for any reason, the process exits non-zero
with a clear message.

Three assertions:

1. `select has_schema_privilege('public','CREATE')` is `false`.
2. `insert into public.users(id,username) values (-1,'probe')` fails with
   SQLSTATE `42501` (`insufficient_privilege`). Any other error — a constraint
   violation, a missing column — means the environment is wrong, which is also a
   refusal but with a different message.
3. `select password_digest from public.users limit 1` fails with `42501`.

Write the error text so an operator knows what to do:

```text
refusing to start: database role can create objects in schema public.
The service must run as a role with only the grants in 0002_grants.sql.
```

Test each by connecting as a superuser and asserting non-zero exit. This is the
test that makes S16 and S20 real; a probe without a failing test proves nothing.

Implement each assertion inside a savepoint. The pass condition is a statement
error, and PostgreSQL aborts a transaction on the first error, so plain
statements would report `25P02 current transaction is aborted` on the second
check and refuse a correctly configured role.

## B5. Health

- `GET /healthz` — returns `200 ok`, touches nothing. Never the database, so a
  database outage does not restart the pod.
- `GET /readyz` — `select 1` plus `select 1 from authz.devices limit 1`. Both
  must succeed within 500 ms or the endpoint returns `503` with a one-line
  reason. A gate that cannot read `devices` must leave rotation (spec §8.4).

Both are excluded from the forwardAuth chain by construction: they are on the
gate's own router, not the application's.

## B6. Server

`cmd/authz/main.go` with subcommands: `serve`, `migrate`. Later phases add
`enroll-new`, `revoke`, `list-devices`.

`serve` does, in order: parse config (fail fast) → connect pool (fail fast, 5 s
timeout) → privilege probe (fail fast) → start listener → on SIGTERM stop
accepting, drain for 10 s, close pool, exit 0.

Log with `slog` to stdout as JSON. One line at startup with the listen address,
host count, and policy file path. No secrets; the DSN is never logged.

Request-id middleware: generate a 16-byte hex id per request, put it in the
context and in a response header. Phase C returns it as `X-Aivan-Request-Id`; in
this phase it only appears in logs.

## B7. Container

```dockerfile
# deploy/Dockerfile
FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/authz ./cmd/authz

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/authz /authz
USER nonroot:nonroot
ENTRYPOINT ["/authz"]
CMD ["serve"]
```

No shell, no package manager, no writable layer needed. The k8s manifest in
`deploy/k8s.yaml` sets `readOnlyRootFilesystem: true`, drops all capabilities,
and sets a `NetworkPolicy` admitting only Traefik — the policy goes in now even
though Phase E is when it matters.

## B8. Checklist

- [ ] `make build` produces `bin/authz`.
- [ ] `authz migrate` against a fresh database creates `authz.*` and records two
      versions; a second run is a no-op.
- [ ] `authz serve` with the correct role starts and logs one line.
- [ ] `authz serve` with a superuser DSN exits non-zero with the refusal text.
- [ ] `authz serve` with a DSN that can read `password_digest` exits non-zero.
- [ ] Each config refusal has a test, and each test fails when its check is
      removed.
- [ ] `/readyz` returns `503` within two seconds of Postgres stopping, and
      `200` after it returns, without restarting the pod.
- [ ] `/healthz` returns `200` while Postgres is down.
- [ ] Image is under 20 MB and runs as nonroot (`kubectl exec ... id`).
- [ ] First commit on `master`.

## B9. Exit criteria

The binary starts under the correct role, refuses a superuser role and a
`password_digest`-capable role, and `/readyz` tracks the database without a
restart loop. Nothing in this phase authenticates anything; do not start on
proofs here.

## Handoff to Phase C

Phase C needs: a running pool, a prepared-statement helper, the `authz` schema,
and the config values for TTLs. It does not need the policy classes to be
correct yet — Phase C tests them.

Deliberate omission: no query counter yet. Phase C adds it, because Phase C is
where a per-request query budget first matters.