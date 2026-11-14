# aivan-authz — initial plan

Status: approved for execution, phase by phase. Derived from
`doc/aivan-initial-spec.md` (revision 2) and `doc/design-notes.md`.

This document sequences the work. Where it disagrees with the specification,
the specification wins and this document is wrong; the amendments that were
needed to make them agree are already applied to the specification and listed
in its revision note.

Read this once for the shape. Work from `doc/implementation-roadmap.md`, which
splits the phases below into one self-contained file each.

## 1. Decisions taken

| Decision | Choice | Why, in one line |
|---|---|---|
| Language | Go 1.26 | Single static binary, Ed25519 and ECDSA in the standard library, no interpreter to patch on a box nobody administers daily |
| Password path in this service | None | Bootstrap is console-only; a gate that cannot read `password_digest` cannot leak it |
| Device scope | Per origin | WebCrypto non-extractable keys cannot leave their origin, so a shared device across hosts is not available without a shared auth host |
| Cookie scope | Host-only, `__Host-` prefix | Follows from per-origin devices; no parent-domain cookie, no host renaming |
| Sessions | Server-side | Requirement S5 wants revoke effective on the next request |
| Algorithms | `ed25519` and `es256`, per device, fixed list | ES256 is the only one every browser has had for a decade; Ed25519 is preferred where the platform can supply it |
| Hot path | One SQL statement, prepared | Keeps the spec's §8.2 budget and makes replay protection a property of the query |
| Policy | Per host, per path prefix | §6.2 plus amendment A19 |

Reversibility: schema lives in plain `.sql` files and the hot path is one
hand-written statement, so the language decision costs at most a rewrite of
`internal/httpx` and `internal/proof` if it ever needs revisiting.

## 2. Shape of the deployment

```text
browser ──TLS──> Traefik ──forwardAuth──> authz:8080/__aivan/verify
                    │                          │ 1 pgx prepared statement
                    │                          └─> Postgres (aivan_core)
                    └── only on 2xx, with X-Aivan-* ──> app pod
```

Three routers per gated host, in priority order:

| Router | Rule | Target | Middleware |
|---|---|---|---|
| gate | `Host(...) && PathPrefix(/__aivan/)` | gate service | none |
| public | `Host(...) && (explicit path list)` | app service | none |
| gated | `Host(...)` catch-all | app service | `forwardAuth` |

The gate router is what makes `Set-Cookie` work: those requests reach the gate
as ordinary proxied requests, so its response headers go straight to the
browser. The same-origin requirement is why the gate is mounted on the
application's host rather than on a host of its own — a WebCrypto key cannot
cross origins.

The `forwardAuth` middleware's `address` points at the gate's cluster service
URL directly (`http://aivan-authz.<ns>.svc:8080/__aivan/verify`), so it does not
travel through any ingress router and cannot recurse.

Public routes must be routed *around* the middleware, not merely allowed by the
gate. If they pass through `forwardAuth`, an auth outage blanks the application,
which spec §8.2 forbids. The gate's `Public` policy class exists only as a
safety net for a path that lands on the gated router by mistake.

## 3. Repository layout

```text
aivan-authz/
  .mise.toml                   go 1.26.5 pinned
  Makefile                     build, test, testdb, lint, image
  go.mod
  cmd/authz/main.go            subcommands: serve, migrate, enroll-new,
                               revoke, list-devices
  internal/config/             env parsing, fail-fast validation, tests
  internal/store/              pgx pool, prepared statements, one-statement helpers
  internal/store/schema/       0001_init.sql, 0002_grants.sql (embedded)
  internal/proof/              canonical string, ed25519, es256, test vectors
  internal/policy/             host + path prefix -> route class
  internal/httpx/              verify, nonce, session, enroll, health, page
  internal/audit/              slog decision records, reason codes
  web/enroll/index.html        one static page, ES module, no build step
  web/enroll/app.js
  deploy/                      Dockerfile, traefik CRDs, k8s manifests
  test/                        integration tests against a real Postgres
  doc/
```

Single binary, subcommands. No external migration tool: `authz migrate` applies
embedded SQL and records versions in `authz.schema_migrations`.

## 4. Data model

All gate-owned tables live in a dedicated schema. `public` stays the
application's.

```sql
create schema authz;

create table authz.schema_migrations (
  version    integer primary key,
  applied_at timestamptz not null default now()
);

create table authz.devices (
  id           uuid primary key,
  user_id      bigint not null references public.users(id),
  origin       text   not null,          -- the one host this key belongs to
  name         text   not null,
  kind         text   not null check (kind in ('phone','tablet','browser')),
  public_key   bytea  not null,
  alg          text   not null check (alg in ('ed25519','es256')),
  proof        text   not null default 'nonce' check (proof in ('nonce','mtls')),
  fingerprint  bytea,
  created_at   timestamptz not null default now(),
  last_seen_at timestamptz,
  revoked_at   timestamptz
);

-- One device per person, per origin, per kind. See the notes below.
create unique index on authz.devices (user_id, origin, kind)
  where revoked_at is null;

-- No foreign key on device_id on purpose: a nonce may only ever be issued for
-- a device id the client claims without revealing whether that device exists
-- (S14). The verify query enforces the binding, and the purge job keeps the
-- table small. issued_at is stored rather than derived from expires_at minus
-- the TTL, so a configuration change does not retroactively move the issuance
-- time of nonces already in flight.
create table authz.nonces (
  nonce_hash bytea primary key,
  device_id  uuid  not null,
  issued_at  timestamptz not null default now(),
  expires_at timestamptz not null
);
create index on authz.nonces (expires_at);

create table authz.sessions (
  token_hash          bytea primary key,
  device_id           uuid  not null references authz.devices(id) on delete cascade,
  created_at          timestamptz not null default now(),
  idle_expires_at     timestamptz not null,
  absolute_expires_at timestamptz not null
);
create index on authz.sessions (idle_expires_at);

create table authz.pending_enrollments (
  id                uuid primary key default gen_random_uuid(),
  user_id           bigint not null references public.users(id),
  origin            text   not null,   -- the host this enrollment is valid on
  kind              text   not null,
  code_hash         bytea  not null,
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null,
  claimed_at        timestamptz,
  claimed_device_id uuid
);

create table authz.audit_log (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  user_id    bigint,
  device_id  uuid,
  host       text not null,
  route      text not null,
  decision   text not null,
  reason     text not null,
  request_id text
);
```

Notes on the shape:

- No `verified_at` on devices. Enrollment carries a signature over the claim
  itself, so a device row exists only for a key that has already proved
  possession. A pending record is the only thing that can produce one.
- One device per person, per origin, per kind, enforced by the partial unique
  index. A second laptop on the same application is a second `browser` device on
  the same origin and is refused. That is intended for v1: it has no distinct
  authority, and the revoke story stays simple. Loosening it is dropping the
  index, not a migration. `kind` still separates phone, tablet and browser, so a
  person holds one of each.
- `origin` on both `devices` and `pending_enrollments` is what makes the
  per-origin decision enforceable rather than advisory. An enrollment record
  claimed on a different host than it was minted for is refused.
- No foreign key from `nonces` to `devices`, because a nonce is issued before
  the service knows whether the device exists (S14). The verify query enforces
  the binding instead.

### 4.1 Privileges

`0002_grants.sql`, run once by the migration role:

```sql
-- The service role is created by the install step, not by this migration.
grant usage on schema authz to aivan_authz;
grant select, insert, update, delete on all tables in schema authz to aivan_authz;
grant usage on sequence authz.audit_log_id_seq to aivan_authz;
grant usage on schema public to aivan_authz;
grant select (id, username, active) on public.users  to aivan_authz;
grant select (id, name)             on public.groups to aivan_authz;
grant select                        on public.groups_users to aivan_authz;
revoke create on schema public from aivan_authz;
```

Column-level grants are what make "the gate cannot read `password_digest`" a
property of the database rather than of code review. `select *` against
`public.users` fails; the fixed column list is also what the hot-path statement
uses.

Both migrations depend on the application's schema. `0001_init.sql` references
`public.users(id)` from `devices`, `sessions` and `pending_enrollments`, and
`0002_grants.sql` grants column-level access to `users`, `groups` and
`groups_users`. Neither can be applied to a database that the application has
not created yet, so the install step applies the gate's migrations after the
application's. Verified in Phase B: a migrate run without `public.users` fails
at `0001_init.sql` and rolls back cleanly.

At boot the gate runs a privilege probe in one transaction and refuses to start
unless it holds:

1. `has_schema_privilege('public','CREATE')` is false.
2. `insert into public.users(...)` fails with `insufficient_privilege`.
3. `select password_digest from public.users` fails with `insufficient_privilege`.

This is S16 plus the new S20. Assertions 2 and 3 each run inside a savepoint:
the passing outcome is a statement error, and PostgreSQL aborts a transaction on
the first error, so without savepoints a correctly configured role would be
refused at startup.

## 5. Wire protocol

### 5.1 Canonical string

```text
aivan-v1 \n
METHOD \n
SCHEME://HOST \n
REQUEST-TARGET \n
SHA256(body) \n
nonce \n
timestamp
```

`REQUEST-TARGET` is path plus `?query`, taken verbatim from `X-Forwarded-Uri`.
The browser computes `location.pathname + location.search`, which uses the same
shape (no trailing `?` when the query is empty). Rules:

- If the request target cannot be reproduced from what the client sees — a
  path-normalising middleware, a rewrite, a refused re-encoding — the gate
  refuses rather than guesses. Failing is recoverable; silently signing a
  different resource is not.
- The query string survives byte for byte. The path does not: Traefik's
  entrypoint decodes percent-encoded unreserved characters and uppercases hex
  digits before routing, so `%41` arrives as `A`, `%7E` as `~`, `%2E` as `.`
  and `%2f` as `%2F`, while the browser's `location.pathname` keeps the client's
  form. Dot-segments and duplicate slashes are normalised too, but the browser
  does that as well before sending. Compare verbatim and refuse on mismatch;
  never normalise the client's string to make it match, because two distinct
  client strings would then produce one target. Observed values are in
  `doc/traefik-contract.md`; Phase C's test vectors use only characters that
  survive normalisation.
- No `StripPrefix` or `ReplacePath` may sit before `forwardAuth` on a gated
  route. Recorded in the CRD comments, and confirmed by observation: with the
  strip first, the auth hop sees the stripped path and the client's signature
  cannot match.
- `SHA256(body)` is the lowercase hex digest of the exact bytes, or the digest
  of the empty body for GET/HEAD.

Go and the browser share one set of golden vectors at
`internal/proof/testdata/canonical.json`. The browser test at Phase F reads the
same file, so a drift between the two implementations fails a test rather than
a user.

### 5.2 Routes

| Method | Path | Purpose |
|---|---|---|
| ANY | `/__aivan/verify` | forwardAuth target; must accept every method |
| POST | `/__aivan/nonce` | issue a single-use nonce for a claimed device id |
| POST | `/__aivan/session` | mint a session from a signed proof |
| DELETE | `/__aivan/session` | logout |
| GET | `/__aivan/enroll` | the one static page |
| POST | `/__aivan/enroll` | claim a pending enrollment with a signed key |
| GET | `/healthz` | liveness, no database |
| GET | `/readyz` | readiness, database reachable and the probe statement runs |

`/__aivan/*` is served by the gate directly through its own router, so
`Set-Cookie` works there. This is why session minting is a route and not a side
effect of `/__aivan/verify`: Traefik forwards a cookie from an auth `200` only
when it appears in `addAuthCookiesToResponse`, and a mint-per-request would cost
a write per request.

### 5.3 Nonce issuance

Unauthenticated by necessity — the client needs a nonce before it can sign.
Consequences, all deliberate:

- Always returns `200` with a nonce, even for a device id that does not exist,
  or the endpoint becomes a device oracle (S14). Binding is enforced at verify.
- Rate limited per source IP, with a global cap and a purge ticker, so it
  cannot be used to fill the table.
- TTL 120 s; the nonce row is deleted by the verify statement.

### 5.4 Verify, in one statement

```sql
with consumed as (
  delete from authz.nonces
   where nonce_hash = $1
     and device_id  = $2
     and expires_at > now()
  returning device_id, issued_at
)
select d.id, d.public_key, d.alg, d.revoked_at, d.user_id, d.origin,
       u.username, u.active, c.issued_at,
       coalesce(array_agg(g.name order by g.name)
                filter (where g.name is not null), '{}') as roles
  from consumed c
  join authz.devices d on d.id = c.device_id
  join public.users u  on u.id = d.user_id
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 group by d.id, d.public_key, d.alg, d.revoked_at, d.user_id, d.origin,
          c.issued_at, u.username, u.active;
```

Order of operations inside a request: consume, then check the timestamp against
both the skew window and `issued_at`, then check `d.origin` equals
`X-Forwarded-Host`, then verify the signature against the returned public key,
then evaluate policy. Consume-first is what makes a replay lose the race, and
the origin check is what makes per-origin devices real: a key enrolled on one
application is refused by another even with a valid signature. A row that comes
back with `revoked_at` set is a denial after the nonce is spent, which is
correct — the nonce is single-use regardless of outcome.

`last_seen_at` is not updated on this path. It is updated by the session mint
and by a background sweep, because a write per verify breaks the one-round-trip
budget.

The session path uses the same shape keyed on `token_hash`, joining through to
the device so a revoke invalidates sessions with no second query.

### 5.5 Sessions

- 32 random bytes, base64url. The cookie carries the token; the table stores
  `sha256(token)`, so a database read does not yield a usable cookie.
- `__Host-aivan_session; Path=/; Secure; HttpOnly; SameSite=Lax`. The `__Host-`
  prefix forbids a `Domain` attribute, which is exactly the host-scoping this
  plan wants.
- Idle 15 min, absolute 8 h. The idle expiry is pushed back only when it has
  moved more than 60 s, so a busy session costs at most one write a minute.
- Logout deletes the row. Revoke deletes every row for the device in the same
  transaction as `revoked_at`.

### 5.6 CSRF

State-changing requests under a cookie session require
`Sec-Fetch-Site: same-origin` or `none`, or an `X-Aivan-Csrf` header when the
browser does not send the former. `same-site` is refused: it covers sibling
subdomains, which is not the boundary we want. A request carrying a signed
device proof skips the check, because the signature covers the intent.

### 5.7 Enrollment

One round trip, one transaction:

```text
POST /__aivan/enroll
{ "code": "...", "kind": "browser", "alg": "es256",
  "public_key": "base64url", "signature": "base64url" }

signature covers:
  aivan-enroll-v1 \n code \n alg \n public_key
```

The signature is checked first, with no database access, because it is
self-contained: it names the key that verifies it. A bad signature therefore
costs nothing and reveals nothing. Then, in one transaction:

```sql
update authz.pending_enrollments
   set claimed_at = now(), claimed_device_id = $new_device_id
 where code_hash = sha256($code)
   and origin     = $forwarded_host
   and claimed_at is null
   and expires_at > now()
returning user_id, origin, kind;
```

with the device row inserted in the same transaction and the whole thing rolled
back when the update affects no row. Order matters: the device id is generated
before the update so it can be recorded as the claimer, and a concurrent second
claim of the same record gets zero rows rather than an orphan device.

Because the claim is signed, a captured POST cannot be repurposed with a
different key, and a guessed code cannot be used without a key that matches the
signature. The `origin` predicate is what stops a code minted for one
application from being spent on another. The `update … returning` is the S9/S10/S11 guard: no pending record,
no device, and the user comes from the record rather than from the request.

The code has enough entropy that hashing it and looking it up by equality is
sufficient; it does not need a constant-time compare, because a timing signal on
a 128-bit random value is not an attack. The enrollment commit writes an
`audit_log` row and logs the device id.

The page is one static HTML file and one ES module. It detects Ed25519 support
and prefers it, falling back to ES256. It is the only user interface this
service has, and it is not a template: no application data is rendered into it.

### 5.8 Denials

| Case | Status | Body / headers |
|---|---|---|
| no proof, `Accept: text/html` | `302` | `Location: /__aivan/enroll?rd=<urlencoded target>` |
| no proof, anything else | `401` | `WWW-Authenticate: Aivan`, nonce endpoint in the body |
| valid proof, insufficient role | `403` | empty |
| body over `AIVAN_MAX_BODY` | `413` | empty |
| gate or database error | `503` | empty |
| replayed or expired nonce | `401` | same body as no proof |

Traefik passes non-2xx from the auth server through untouched, `Location`
included, so the gate owns the redirect and `authSigninURL` stays unused. The
gate must not vary timing or body between "no such device" and "bad signature"
(S14).

## 6. Configuration

Environment only, validated at boot, refusing to start on any of: a missing
database URL, a policy file naming a host not in `AIVAN_HOSTS`, a non-`https`
scheme for any host, a cookie without `__Host-`, or a nonce TTL longer than the
timestamp skew.

| Variable | Default | Notes |
|---|---|---|
| `AIVAN_DB_URL` | — | required; the service role, never the migration role |
| `AIVAN_LISTEN` | `:8080` | |
| `AIVAN_HOSTS` | — | comma-separated; no wildcards |
| `AIVAN_POLICY` | `/etc/aivan/policy.yaml` | per host and path prefix |
| `AIVAN_NONCE_TTL` | `120s` | |
| `AIVAN_SKEW` | `300s` | |
| `AIVAN_SESSION_IDLE` | `15m` | |
| `AIVAN_SESSION_MAX` | `8h` | |
| `AIVAN_MAX_BODY` | `1048576` | below Traefik's ceiling |
| `AIVAN_TRUSTED_PROXY_CIDRS` | cluster pod CIDR | for the rate limiter only |

Policy shape:

```yaml
hosts:
  aivan-hud.home.arpa:
    routes:
      - { prefix: /admin, class: admin }
      - { prefix: /,      class: authenticated }
```

Policy decides *what a route needs*; `devices.origin` decides *whether this key
is valid here at all*. Keeping them separate means a routing mistake cannot
make a device from one application work on another.

## 7. Observability

Two sinks, split by cost:

- **Every decision** goes to structured stdout via `slog`: request id, host,
  method, route, user id or `anonymous`, device id, decision, reason code.
  Never a signature, nonce, cookie, or key.
- **`authz.audit_log`** takes only security-relevant events: denials,
  enrollment, revoke, session mint, logout. A row per allowed request would be
  a write in the hot path and buy nothing the logs do not already hold.

A `X-Aivan-Request-Id` is generated at the gate and returned with the identity
headers, so an application error can be joined to a decision.

## 8. Phases

Each phase ends with a criterion that can be demonstrated, and Phase A exists
because three of the assumptions this plan rests on are middleware behaviours
that are cheaper to confirm than to debug later.

### Phase A — prove the Traefik contract (no gate code)

Build a throwaway echo service and put it behind the exact middleware
configuration, on a test host.

- [x] Deploy the echo service and a `Middleware` CRD with
      `authResponseHeadersRegex: "^X-Aivan-"`, an explicit
      `authRequestHeaders`, `preserveRequestMethod: true`,
      `forwardBody: true`, `maxBodySize: 1048576`, `preserveLocationHeader: true`.
- [x] Confirm a client-supplied `X-Aivan-User` is stripped before the echo
      service sees it, and that the value set by the auth response arrives.
- [x] Confirm a `401` from the auth service reaches the client with its body and
      `WWW-Authenticate` unchanged, and that a `302` arrives with `Location`
      intact. Check the `302` both with and without `preserveLocationHeader`:
      the default rewrites it to the auth service's cluster address.
- [x] Confirm a `200` from the auth service does not deliver `Set-Cookie`, then
      confirm `addAuthCookiesToResponse` does, and record which behaviour the
      gate route design relies on (none — but verify the claim).
- [x] Record the exact values Traefik sends for `X-Forwarded-Method`, `-Proto`,
      `-Host`, `-Uri`, including a request with a query string and one with a
      percent-encoded path.
- [x] Confirm what the client receives when the auth service is stopped, and
      record the status. Spec §8.2 requires a refusal, so an error status is
      acceptable, but the actual value has to be known and written down.
- [x] Write the findings to `doc/traefik-contract.md`.

**Exit:** every line above is recorded with the observed output, and no line
contradicts §2 or §5.1 of this plan.

### Phase B — skeleton, schema, privileges, health

Complete. Record of what was built and observed: `doc/phase-b-record.md`.

- [x] `go.mod`, `.mise.toml` pinning `go@1.26.5`, `Makefile` with `build`,
      `test`, `testdb`, `image`.
- [x] `internal/config` with table-driven tests for every refusal listed in §6.
- [x] `0001_init.sql` and `0002_grants.sql`, embedded, applied by
      `authz migrate`, versioned in `authz.schema_migrations`.
- [x] `authz serve` with graceful shutdown and a request-id middleware.
- [x] `/healthz` that never touches the database; `/readyz` that runs `select 1`
      and one row read against `authz.devices`.
- [x] Boot privilege probe per §4.1, with a test that starts against a
      superuser credential and expects a refusal to start.
- [x] Distroless `Dockerfile`, non-root, `readOnlyRootFilesystem`, no shell.
- [x] First commit.

**Exit:** the binary starts with the correct role, refuses a superuser role, and
`/readyz` turns red within one probe interval of Postgres stopping.

### Phase C — proof, policy, and the hot path

- [x] `internal/proof`: canonical string builder; Ed25519 and ES256 verify;
      fixed algorithm list; golden vectors in `testdata/canonical.json`.
- [x] `internal/policy`: per host and prefix, with a test per class and a
      refusal for an uncovered path.
- [x] `POST /__aivan/nonce`, with the rate limiter and the table cap.
- [x] `ANY /__aivan/verify` and the §5.4 statement, prepared once.
- [x] The denial matrix in §5.8, including the `Accept` split.
- [x] `slog` decision records and reason codes.
- [x] Tests S1–S4, S7, S8, S14, S15, S17, S19, S21.
- [x] A query-counter test asserting exactly one statement per verified
      request, and a benchmark that reports p50/p99.
- [x] A clock injection point, so skew and expiry tests do not sleep.

**Exit:** those requirement tests are green, every one fails when its guard is
removed, and the benchmark holds p99 under 5 ms with the database local.

### Phase D — sessions

- [x] `POST /__aivan/session` minting from a signed proof; `DELETE` for logout.
- [x] Cookie flags per §5.5, with a test asserting `__Host-`, `Secure`,
      `HttpOnly`, `SameSite=Lax`, `Path=/`, and no `Domain`.
- [x] Sliding idle expiry with the 60 s write window, absolute cap enforced.
- [x] CSRF rule per §5.6, `same-site` refused.
- [x] `authz revoke --device <id>` deleting sessions in the same transaction.
- [x] `authz list-devices --username <name>`.
- [x] Tests S5, S13.

**Exit:** a revoked device's live session is refused on the next request, a
cross-site POST under a cookie is refused, and a busy session issues at most one
write a minute (asserted from the query counter).

### Phase E — put aivan-hud behind the gate

- [x] Replace hud's single ingress with the three routers in §2: the gate
      router (`/__aivan/`), a public router for the list in `doc/auth.md`, and a
      gated catch-all carrying the `Middleware` CRD.
- [x] `current_user` and `require_admin!` in hud read `X-Aivan-User-Id` and
      `X-Aivan-Roles` on gated routes, and never fall back to `session[:user_id]`
      there.
- [x] A build-tagged `devtools` subcommand that mints a session for a manual
      test of the proxy loop, excluded from the production image. Built in
      Phase E and removed in Phase F, which replaced it with real enrollment;
      the tag and the selftest routes went in Phase G.
- [x] `NetworkPolicy` admitting only Traefik to the gate; no `Ingress` for it.
- [x] S21 against the cluster: a device enrolled for hud, presented to a second
      test host behind the same gate, must be refused.

**Exit:** acceptance 1, 3, 4 and 10 hold with the dev-minted session; a forged
`X-Aivan-User` reaches neither hud nor the gate; a hud device is refused on the
test host.

### Phase F — enrollment

Complete, with the deviations recorded in `doc/phase-f-record.md`. Two of them
change what the specification says: the code is 26 Crockford characters from 16
bytes (the plan's "32 characters" is unreachable at that entropy), and ES256
accepts both the raw `r||s` form browsers emit and the DER form Phase C assumed.

- [x] `authz enroll-new --username <name> --origin <host> --kind <kind>`
      printing a code once, refusing when that person already has an active
      device of that kind on that origin.
- [x] `GET /__aivan/enroll` page and `POST /__aivan/enroll` per §5.7.
- [x] Shared canonical vectors exercised from the browser test.
- [x] Tests S9, S10, S11, including a captured-POST key swap and a replayed
      claim.
- [x] Remove the Phase E dev mint from the shipped build.

**Exit:** acceptance 2 in a real browser on the cluster, from an empty profile;
wrong code, expired record, and a second claim of the same record are all
refused; the enrolled device survives a gate restart.

### Phase G — hardening and operations

- [x] `413` at the gate with Traefik's `maxBodySize` as the ceiling above it
      (S18), and a test for a body one byte over the limit.
- [x] Purge ticker for nonces and idle sessions.
- [x] Log hygiene test: a request carrying key material, a signature, and a
      cookie produces no such value in the log output.
- [x] k6 profile per spec §8.2, mixed accept and deny, with the report kept.
- [x] Kill-the-gate test: gated routes refuse, public routes keep serving.
- [x] Runbook: bootstrap order, add a device, revoke a device, rotate the
      database credential, recover from a lost phone (procedure only, per spec §10).

**Exit:** acceptance 5–9 hold and the runbook has been followed once end to end
by someone other than its author.

### Deferred

Grants (spec §6.3), mTLS, phone push, lost-device recovery, second admin,
certificate renewal, and multi-replica readiness. Grants block no acceptance
item and the canonical-string and signature code carries over unchanged.

## 9. Bootstrap, in order

Two console steps, split because the gate cannot write `public.users` by
design:

```bash
# 1. the person and admin membership — the application's own task
kubectl exec -it -n aivan deploy/aivan-hud -- \
  bundle exec rake admin:create EMAIL=... ADMIN_USERNAME=...

# 2. the first pending enrollment — the gate's task, prints a code once
kubectl exec -it -n aivan deploy/aivan-authz -- \
  authz enroll-new --username <name> \
    --origin aivan-hud.home.arpa --kind phone
```

The code is short-lived and single-use, and it is bound to the origin it was
minted for. Step 2 refuses once that person has an active device of that kind on
that origin, so a forgotten enrollment does not accumulate credentials.

## 10. Requirement to test map

| Requirement | Phase | Test kind |
|---|---|---|
| S1 replayed nonce | C | integration |
| S2 any covered field changes | C | unit, table-driven over the canonical fields |
| S3 expired nonce | C | integration, injected clock |
| S4 clock skew | C | integration, injected clock |
| S5 revoked device and its sessions | D | integration |
| S6 client header cannot reach the app | A, E | e2e against the cluster |
| S7 no roles cannot act as roles | C | integration |
| S8 device of A cannot act as B | C | integration |
| S9 claim without a pending record | F | integration |
| S10 claim with a wrong code | F | integration |
| S11 claim cannot bind a different user | F | integration |
| S12 retired password | withdrawn | no password path exists; the column grant test replaces it |
| S13 CSRF under a cookie | D | integration |
| S14 denial reveals nothing | C | integration, comparing status and body across both branches |
| S15 constant-time compare | C | unit plus review note; Ed25519 verify is not a secret-dependent branch |
| S16 credential cannot write outside its tables | B | boot refusal test |
| S17 unknown algorithm | C | unit |
| S18 oversized body | G | integration plus e2e |
| S19 query string covered | C | unit plus e2e |
| S20 credential cannot read `password_digest` | B | boot refusal test |
| S21 device bound to one origin | C, E | integration with two hosts: a valid proof on the wrong host |

## 11. Risks

**The request target may not round-trip.** Traefik hands over
`X-Forwarded-Uri`, and the browser computes the same string from `location`.
Percent-encoding normalisation is the place these two diverge. Phase A measured
it: the query string survives byte for byte, while the entrypoint decodes
percent-encoded unreserved characters and uppercases hex digits in the path, so
`%41`, `%7E`, `%2E` and lower-case `%2f` arrive differently from what the browser
computed. Mitigation, as observed: the gate refuses what it cannot reproduce,
and the shared test vectors use only characters that survive normalisation. The
browser still re-reads `location` immediately before signing rather than caching
it from page load.

**Public routing is a deployment property, not a gate property.** A path added
to the application without a router rule lands on the gated router and starts
requiring a session. Mitigation: the gate logs `reason=class_defaulted` when a
request matches no explicit rule, and Phase G exercises the public list.

**Per-origin devices cost a re-enrollment per application.** Accepted for v1.
The escape hatch is a shared auth host with a parent-domain cookie, which is a
rename plus a certificate, not a redesign.

**One more moving part in the critical path.** The gate is now able to fail
closed on every protected route. Mitigation: `/readyz` on the database,
liveness independent of it, no restart loop on a database outage, and the public
surface outside the chain.

## 12. Still open

- Whether aivan-hud keeps its own password login for anything once the gate is
  live. It is app-local and outside this service; `/admin` will require the gate
  either way.
- Exact nonce and session lifetimes, to be set against real usage after Phase D.
- Registration policy for people other than the first admin. Spec §10 defers
  it; the pending-enrollment record is the natural mechanism when it is
  decided.