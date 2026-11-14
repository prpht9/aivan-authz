# aivan-authz runbook

For an operator who has not read the plan. Every command here was run on
2026-11-13 against the install it describes (k3s, Traefik 3.7.13, PostgreSQL
14.5 in namespace `aivan-core`, gate and `aivan-hud` in `hermes-agent`).

Placeholders:

```console
export AIVAN_NS=hermes-agent          # namespace holding aivan-hud and aivan-authz
export HUD_HOST=aivan-hud.home.arpa   # the gated host
```

Every `kubectl` command below names its namespace explicitly. Nothing here
requires cluster-admin; the role that runs `authz` needs only the grants in
`deploy/roles.sql`.

---

## 1. Bootstrap, in order

The application creates the person; the gate creates the credential. Neither can
do the other's half.

### 1a. The person, and admin membership

This is the application's task, not the gate's. In `aivan-hud` it is the
registration page (or a console insert for the first admin). The gate only reads
`public.users.id`, `username` and `active`, and the group names in
`public.groups`/`public.groups_users`.

Confirm the person exists and is active:

```console
$ kubectl -n aivan-core exec aivan-core-1 -- psql -U postgres -d aivan_core \
    -c "select id, username, active from public.users"
 id | username | active
----+----------+--------
 10 | chris    | t
```

### 1b. The first enrollment code

`admin:create` is the application's own first-admin step. Once that person
exists, the gate mints their first device:

```console
$ kubectl -n aivan-core port-forward svc/aivan-core-rw 5544:5432 &
$ export AIVAN_DB_URL='postgres://aivan_migrations:<pw>@127.0.0.1:5544/aivan_core?sslmode=disable'
$ export AIVAN_HOSTS=aivan-hud.home.arpa
$ ./authz enroll-new --username chris --origin aivan-hud.home.arpa --kind browser
```

Output:

```text
enrollment code: Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M
user: chris (id 10)
origin: aivan-hud.home.arpa
kind: browser
record: 9a82a19a-7e53-41d9-8a8f-2a3c0d833be5
expires_at: 2026-11-14T04:35:59Z

Enter the code at https://aivan-hud.home.arpa/__aivan/enroll within 15m0s. It is shown once.
```

The code is 26 Crockford characters with a dash every four.

Two facts an operator must know:

- The command needs the database credential and therefore a port-forward. It is
  a subcommand of the binary, not a route, which is what keeps it
  operator-only.
- **The code is printed once.** Only its digest is stored. There is no
  `--show` and no way to recover it; a lost code means minting another.

The first command in the list (`admin:create`) requires a typed password
because the application's own login is a password login. The second prints a
code once and never again.

### 1c. What the person does

Open `https://aivan-hud.home.arpa/__aivan/enroll`, paste the code, press
Enroll. The page generates a P-256 or Ed25519 key in the browser (it cannot be
exported), signs the claim, and receives a session cookie.

---

## 2. Add a device

1. Mint a code (above) for that person, that host, and the kind `browser`.
2. Open the gated host, which redirects to `/__aivan/enroll?rd=…`.
3. Paste the code.

What the operator sees when the person already has a live device of that kind:

```console
$ ./authz enroll-new --username chris --origin aivan-hud.home.arpa --kind browser
enroll-new: user "chris" already has a live browser device on aivan-hud.home.arpa
(62aa0ecf-c79c-3792-fec6-5dd72c70a5ec); end it with
`authz revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec` before minting another
```

That is deliberate: one live device per person, per host, per kind. A second
browser on the same host is a revoke-then-enroll, not a second credential.

Codes expire after 15 minutes and can be claimed once. A claim that fails
(wrong code, expired, already claimed, wrong host) is the same 403 with the same
body, so the person retries rather than learning which it was.

---

## 3. Revoke a device

```console
$ ./authz revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec
revoked 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec for user 10; 3 session(s) deleted
```

Open tabs stop working on their next request. Observed: with a cookie session
under continuous load, 330 requests were allowed and then every request from the
331st was `401` with reason `device_revoked`, with no `500`s. The gate joins the
session through `authz.devices` on every request, so the revoke needs no
propagation delay and no session-list walk.

A revoked device keeps its row and its history; `list-devices` shows it with a
`REVOKED` timestamp. Revoking again is a no-op that says so.

---

## 4. Lost phone

There is no recovery of the key. The private half was generated on the device,
cannot be exported, and the gate has only the public half. State that plainly to
the person; do not look for a way to restore it.

The procedure is:

1. `./authz list-devices --username <name>` to find the device id.
2. `./authz revoke --device <id>`.
3. `./authz enroll-new --username <name> --origin <host> --kind <kind>` and hand
   them the new code.

The old device is now refused everywhere; the new one starts with no sessions.
Spec §10 lists recovery of a lost device as out of scope; this revoke-and-remint
is the whole procedure.

---

## 5. Rotate the database credential

The gate's credential is `aivan_authz`, created by `deploy/roles.sql` and granted
by `0002_grants.sql`. Rotating it is three steps and one restart.

```console
# 1. A new password, and a new role with the same grants. The grants are in
#    0002_grants.sql; a role that lacks them is refused at boot (see below).
$ kubectl -n aivan-core exec aivan-core-1 -- psql -U postgres -d aivan_core -c \
    "create role aivan_authz_v2 login nosuperuser nocreatedb nocreaterole password '<new-pw>'"
$ kubectl -n aivan-core exec aivan-core-1 -- psql -U postgres -d aivan_core -f - < deploy/roles.sql
# (edit roles.sql first: the new name, and the CREATE ROLE lines commented out
#  on a second run, because PostgreSQL has no CREATE ROLE IF NOT EXISTS)

# 2. The secret.
$ kubectl -n "$AIVAN_NS" create secret generic aivan-authz-db \
    --from-literal AIVAN_DB_URL='postgres://aivan_authz_v2:<new-pw>@aivan-core-rw.aivan-core.svc.cluster.local:5432/aivan_core?sslmode=require' \
    --dry-run=client -o yaml | kubectl apply -f -

# 3. Restart, which is what makes the pod read the new secret.
$ kubectl -n "$AIVAN_NS" rollout restart deploy/aivan-authz
$ kubectl -n "$AIVAN_NS" rollout status deploy/aivan-authz
```

The pod reads the secret at start, not per request, so the restart is required.

### Recognising a privilege refusal as configuration

If the new role holds more than `0002_grants.sql` intends, the gate refuses to
start and the pod enters `CrashLoopBackOff`. That is the design, not a bug:

```console
$ kubectl -n "$AIVAN_NS" logs deploy/aivan-authz --previous
refusing to start: database role can create objects in schema public.
The service must run as a role with only the grants in 0002_grants.sql.
```

```text
refusing to start: database role can read public.users.password_digest.
The service must run as a role with only the grants in 0002_grants.sql.
```

The fix is to run the grants, not to change the gate. `revoke create on schema
public from <role>` is the first line of that fix; the column grants are the
second.

---

## 6. What each status means

| Status | Produced by | Meaning | Where to look |
|---|---|---|---|
| `401` | gate | No valid proof and no valid cookie. The body is constant: `authentication required: POST /__aivan/nonce`. | decision log: the `reason` field |
| `403` | gate | The proof was valid and the policy refused it: role insufficient, host unknown, plaintext arrival, or a CSRF failure. | decision log: `reason` |
| `404` | the application | The gate allowed the request; the application has no such route. Not the gate's refusal. | the application's log |
| `413` | gate | The body exceeded `AIVAN_MAX_BODY`. | decision log: `reason: body_too_large` |
| `429` | gate | The nonce endpoint's rate limiter. A page that reloads too fast, or a client with no proof retrying in a loop. | decision log: `reason: rate_limited` |
| `503` | gate | The gate could not decide: the database failed, or the nonce table is at its cap. | gate log: `database error` or `nonce_table_full` |
| `500` | Traefik | The gate is unreachable. Traefik's `forwardAuth` has no other way to fail closed. | `kubectl get pod -l app=aivan-authz` |

### Reason codes that mean a misconfiguration

| Reason | What it means |
|---|---|
| `host_unknown` | A request arrived for a host not in `AIVAN_HOSTS`. A router is pointing at the gate with the wrong host, or the policy and the environment disagree. |
| `plain_http` | A request reached the gate over `http`. A router is missing `tls:` or the entrypoint is wrong. |
| `forwarded_missing` | Traefik did not set `X-Forwarded-Method`, `-Proto`, `-Host` or `-Uri`. A proxy between Traefik and the gate is stripping them. |
| `class_defaulted` | A path reached the gate with no policy entry. The gate requires a proof anyway; add the prefix to the policy. |
| `nonce_table_full` | The purge ticker has not run for a long time, or something is issuing nonces far faster than they are consumed. A symptom, not an attack in itself. |
| `database_error` | The gate could not reach or read its database. Check `/readyz` first. |
| `alg_unsupported` | A device row names an algorithm outside the fixed list. A hand-edited row, or an old schema. |

These mean an attack or a bad client:

| Reason | What it means |
|---|---|
| `nonce_unknown` | A nonce that was never issued, or was already spent. Replay, or a client reusing a nonce. |
| `replay` | The same nonce presented twice. |
| `timestamp_skewed` | The request's clock is more than `AIVAN_SKEW` from the gate's. The user's clock is wrong, or a capture is being replayed later. |
| `bad_signature` | A signature over the canonical string that does not verify. A different key, a different field, or a tampered request. |
| `rate_limited` | More nonce requests than the token bucket allows. |
| `device_revoked` | The device was revoked. A revoke doing its job, or a stolen device that has been cut off. |
| `csrf_samesite` / `csrf_missing` | A state-changing request under a cookie without the required proof. A cross-site attempt, or an old client. |

---

## 7. Where the logs are, and three queries

Decisions are JSON on the gate's stdout, at `info`:

```console
$ kubectl -n "$AIVAN_NS" logs deploy/aivan-authz -f
{"time":"2026-11-14T04:02:44Z","level":"INFO","msg":"decision",
 "request_id":"7bafd90a…","host":"aivan-hud.home.arpa","method":"GET",
 "route":"/admin","user_id":"10","device_id":"62aa0ecf-…",
 "decision":"allow","status":200}
```

A denial carries a `reason`; an allow carries none. No line contains a
signature, a nonce, a cookie, a public key or the DSN — the handler drops any
attribute whose name is one of those, so the guarantee does not depend on a
review.

`authz.audit_log` holds the security-relevant events only: enrollments,
revokes, and the console's own actions.

```console
$ kubectl -n aivan-core exec aivan-core-1 -- psql -U postgres -d aivan_core
```

```sql
-- Denials by reason, last 24 hours. A spike in one reason is the signal.
select reason, count(*)
  from authz.audit_log
 where decision = 'deny' and at > now() - interval '24 hours'
 group by reason order by 2 desc;

-- Enrollments in the last day.
select at, host, user_id, device_id, reason
  from authz.audit_log
 where decision = 'enroll' and at > now() - interval '1 day'
 order by at desc;

-- Devices not seen in 30 days: candidates for revoke.
select d.id, u.username, d.kind, d.origin, d.last_seen_at
  from authz.devices d join public.users u on u.id = d.user_id
 where d.revoked_at is null
   and (d.last_seen_at is null or d.last_seen_at < now() - interval '30 days')
 order by d.last_seen_at nulls first;
```

The gate's own request id is returned as `X-Aivan-Request-Id` and forwarded to
the application, so an application error and a gate decision can be joined on
it.

---

## 8. Rollback: take the gate out

Deleting the gate's routing puts `aivan-hud` back on its own cookie login. The
public surface is untouched either way.

```console
$ kubectl -n "$AIVAN_NS" delete -f aivan-hud/deploy/routing.yaml
$ kubectl -n "$AIVAN_NS" get ingressroute
No resources found in hermes-agent namespace.
```

Confirm `/admin` works on hud's own cookie:

```console
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
200
```

That `200` is hud's own password login (a redirect to `/login` follows if the
browser has no cookie). The gate's Service can stay deployed and unused, or be
scaled to zero; with no router naming it, nothing calls it.

To put the gate back:

```console
$ envsubst < aivan-hud/deploy/routing.yaml | kubectl apply -f -
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
401
```

---

## 9. The `413` boundary

The gate refuses a body above `AIVAN_MAX_BODY` (1048576) with its own `413`.
Traefik's `forwardAuth.maxBodySize` is the hard ceiling above it (2097152), and
a body above that is refused by Traefik with its own `401`. Both numbers are in
the manifests: the gate's in the Deployment's environment, the ceiling in
`deploy/routing.yaml` and in the policy file's `maxBody`.

The gate refuses to start if the policy file's `maxBody` is not above
`AIVAN_MAX_BODY`, because the two live in different files and will drift.

Observed on the cluster:

| Body | Result | Who answered |
|---|---|---|
| 1048575 bytes | `200`, application received `Content-Length: 1048575` and read all 1048575 bytes | gate allowed |
| 1048577 bytes | `413`, empty body | the gate |
| 2097153 bytes | `401`, empty body | Traefik, before the gate |

The third row is a documented limitation, not a bug: the ceiling has to be
somewhere, and Traefik answers first. The operator-visible consequence is that a
client sending an absurd body sees a `401` that names nothing. The gate's log
shows no decision for it, which is how an operator tells the two apart.

---

## 10. Failure drills, and what to expect

Each was run once; the observed behaviour is what follows.

**Kill the gate.**

```console
$ kubectl -n "$AIVAN_NS" scale deploy aivan-authz --replicas=0
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
500
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/
200
```

`/admin` is refused with Traefik's `500` (empty body, in milliseconds), and the
public surface keeps serving. That is spec §8.2: failure is closed, and the
public surface is not behind the gate.

**Stop Postgres.** `/readyz` turns `503` within one probe interval, `/healthz`
stays `200`, the pod does not restart, and protected routes are refused. When
Postgres returns, `/readyz` goes back to `200` without a restart.

```console
$ kubectl -n aivan-core exec aivan-core-1 -- bash -c \
    'for p in /proc/[0-9]*; do case "$(cat $p/comm)" in postgres) kill -STOP ${p#/proc/};; esac; done'
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/readyz
503
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/healthz
200
$ kubectl -n aivan-core exec aivan-core-1 -- bash -c \
    'for p in /proc/[0-9]*; do case "$(cat $p/comm)" in postgres) kill -CONT ${p#/proc/};; esac; done'
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/readyz
200
```

The freeze is used instead of deleting the pod because CNPG restarts it in a few
seconds, which is too short a window to observe. It is the same failure from the
gate's side: the database accepts a connection and never answers.

**Revoke during traffic.** With a cookie session under continuous load,
`authz revoke --device <id>` stops the session on its next request, with no
`500`s. Observed: 330 allowed, then every request `401` with
`reason: device_revoked`.

**Clock skew.** A client whose clock is ten minutes off gets `401` with the
constant body and `reason: timestamp_skewed`. This is the failure a user will
actually hit, and the body tells them nothing they can act on; the enrollment
page and the runbook both say to check the clock.

**Replay.** Send one signed request twice. The first is `200`, the second is
`401` with `reason: nonce_unknown`. Observed with the same nonce, timestamp and
signature.

`test/drill/sign` is the tool for the last three:

```console
$ go build -o /tmp/sign ./test/drill/sign
$ /tmp/sign -target https://aivan-hud.home.arpa -path /admin \
    -device <uuid> -key device.jwk -insecure -repeat 2
attempt 1: 200 OK body="<!DOCTYPE html>…"
attempt 2: 401 Unauthorized body="authentication required: POST /__aivan/nonce"
```

---

## 11. Load test

See `doc/latency-report.md`. The short version:

```console
$ eval "$(go run ./test/load/seed -dsn "$MIGRATION_DSN" -user 1 -count 100000 -jwk-env)"
$ k6 run -e AIVAN_PROFILE=steady200 -e AIVAN_VIA=handler \
    -e AIVAN_TARGET=http://127.0.0.1:8080 \
    -e AIVAN_LOAD_DEVICE="$AIVAN_LOAD_DEVICE" -e AIVAN_LOAD_JWK="$AIVAN_LOAD_JWK" \
    test/load/verify.js
```

`AIVAN_VIA=traefik` requests a gated application path and lets the middleware
make the auth call; `AIVAN_RESOLVE=host:address` keeps the gated hostname in the
`Host` header when dialling a local proxy.
