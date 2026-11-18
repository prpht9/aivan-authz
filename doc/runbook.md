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
requires cluster-admin.

Amended 2026-11-14 for `doc/schema-handover.md`. Two things changed for an
operator:

- **The schema is aivan-hud's.** `rake db:migrate` in that project applies it,
  as its migration role. There is no `authz migrate`.
- **The operator commands are `authz-admin`,** a binary built on a workstation
  and never put in an image. `enroll-new`, `revoke`, `list-devices`, `purge` and
  the `service` commands all live there. The gate's image contains only `serve`.

The commands below are written against `authz-admin/`. Nothing about the gate's
runtime changed: the probes, the reason codes, the `413` boundary and the
latency numbers are as they were.

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

### 1b. The schema, then the first enrollment code

The schema is aivan-hud's, so it is applied from that project, as the migration
role, before anything on this side can start:

```console
$ kubectl -n aivan-core port-forward svc/aivan-core-rw 15432:5432 &
$ cd /path/to/aivan-hud
$ DATABASE_URL='postgres://aivan_migrations:<pw>@127.0.0.1:15432/aivan_core?sslmode=disable' \
    bundle exec rake db:migrate
$ bundle exec rake db:check_grants     # asserts the matrix and the denials
```

`admin:create` is the application's own first-admin step. Once that person
exists, their first device is minted from the operator binary, on the
workstation, against the same port-forward:

```console
$ export AIVAN_DB_URL='postgres://aivan_migrations:<pw>@127.0.0.1:15432/aivan_core?sslmode=disable'
$ export AIVAN_HOSTS=aivan-hud.home.arpa
$ ./authz-admin enroll-new --username chris --origin aivan-hud.home.arpa --kind browser
```

There is no `kubectl exec` path that mints: the gate's image does not contain
the command. That is deliberate — a process compromised in the pod cannot create
a credential.

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

### The square, and the phone

Run at a terminal, the command also draws a QR square under the text. A phone
camera scans it and opens the enrollment page with the code already filled in.
The text above is unchanged, so anything that parses the output still works.

```console
$ ./authz-admin enroll-new --username chris --origin aivan-hud.home.arpa --kind phone
enrollment code: Q3N2-QA2B-P4BB-FAN9-DTW1-RRXD-2M
user: chris (id 10)
origin: aivan-hud.home.arpa
kind: phone
record: 9a82a19a-7e53-41d9-8a8f-2a3c0d833be5
expires_at: 2026-11-14T04:35:59Z

Enter the code at https://aivan-hud.home.arpa/__aivan/enroll within 15m0s. It is shown once.

Scan to open the enrollment page on a phone:

▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█ ▄▄▄▄▄ █▀▀▄█▀▄▀█ ▄▄▄▄▄ █▀█ ▄▄▄▄▄ █
█ █   █ █▀█▄▄ ▀▀█ █   █ █▀▀ █   █ █
█ █▄▄▄█ █▀▄▀▀▄▀ █ █▄▄▄█ █ ▀ █▄▄▄█ █
█▄▄▄▄▄▄▄█▄▀▄█▄▀▄█▄▄▄▄▄▄▄█▄▀▄█▄▄▄▄▄▄▄█
█ ▀▄▀▄ ▄▀▀█ ▄ ▀█ ▄▀▀  ▀▄█▄▀▄█ ▀▄▀▄ ▄▀█
█▄▄▀▀█▀▄▄█▄ ▄▀▀▀ █▀ █ ▄▀▄▄▀█▄▄▀▄▀▄ ██
█ ▄▄▄ █▀▄▀ ▀▄▀▀▄▄▄ ▀▀▀▄▀█▄▀▄█ ▄▄▄ █▀█
█ █▄▄▄█ █▀▀▀▀▀▀▄▀▀ ▄▀▀▄▀▀▀▄▀█ █▄▄▄█ ██
█▄▄▄▄▄▄▄█▄▄█▄▄█▄▄▄█▄█▄█▄▄█▄▄█▄▄▄▄▄▄▄██
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
```

`--qr` chooses the drawing:

| Value | What it draws |
|---|---|
| `auto` (default) | the square when stdout is a terminal, nothing when it is redirected |
| `blocks` | the square with half-block glyphs, forced black-on-white |
| `ascii` | the square with two characters per module and no escape codes |
| `none` | the text block only, which is what a script sees by default |

The default is `auto`, so a command in a pipeline or a log file gets exactly the
output it got before the square existed. `blocks` sets its own colours because
a dark terminal would otherwise draw a light-on-dark square, which a camera
refuses.

Two facts an operator must know:

- The command needs the database credential and therefore a port-forward. It is
  a subcommand of a binary that is not in any image, which is what keeps it
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
2. Open the gated host. With no session the gate sends the browser to
   `/__aivan/login?rd=…`, which mints from a key the browser already holds or
   links to `/__aivan/enroll?rd=…` when it holds none.
3. On the enrollment page, paste the code.

A person who has enrolled this browser before signs in again with the code they
do not have: the login page re-proves the stored key and lands on the page they
asked for. Re-enrolling is only for a browser with no key, or a revoked one.

What the operator sees when the person already has a live device of that kind:

```console
$ ./authz-admin enroll-new --username chris --origin aivan-hud.home.arpa --kind browser
enroll-new: user "chris" already has a live browser device on aivan-hud.home.arpa
(62aa0ecf-c79c-3792-fec6-5dd72c70a5ec); end it with
`authz-admin revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec` before minting another
```

That is deliberate: one live device per person, per host, per kind. A second
browser on the same host is a revoke-then-enroll, not a second credential.

Codes expire after 15 minutes and can be claimed once. A claim that fails
(wrong code, expired, already claimed, wrong host) is the same 403 with the same
body, so the person retries rather than learning which it was.

---

## 3. Revoke a device

Revocation is a hud action: `/admin`, or a person revoking their own phone. The
command below is the break-glass path for when hud is down.

```console
$ ./authz-admin revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec
revoked 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec for user 10; 3 session(s) deleted
```

The gate cannot revoke. Its credential holds no `EXECUTE` on
`authz.revoke_device()`, so a compromised gate cannot cut off every device in the
household — which would be a denial of service on the whole system.

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

1. `./authz-admin list-devices --username <name>` to find the device id.
2. `./authz-admin revoke --device <id>`.
3. `./authz-admin enroll-new --username <name> --origin <host> --kind <kind>` and hand
   them the new code.

The old device is now refused everywhere; the new one starts with no sessions.
Spec §10 lists recovery of a lost device as out of scope; this revoke-and-remint
is the whole procedure.

---

## 4a. Ship a new build

Three rake tasks, and the third is the one that matters.

```console
$ export AIVAN_NS=hermes-agent
$ rake push           # build the image, push it, confirm the registry took it
$ rake deploy:verify  # read-only: what is running, and is it HEAD?
$ rake deploy         # push, apply, roll, and verify again
```

`rake push` does not trust that a push with no error landed. It reads the tag's
manifest back from the registry and compares its config digest with the image it
just built, so a push to the wrong tag or a registry that dropped the blob is a
failure here rather than a pod that runs yesterday's bytes.

`rake deploy:verify` is read-only and safe to run at any time. It reports two
things: the ready pod's imageID against the digest the registry serves for the
tag, and the `vcs.revision` stamped into the running binary against `HEAD`. Both
have to match. The second check exists because of PA1 in
`doc/pentest-evidence/a.md`: the deployed gate was seven commits behind the tree
with every build step reporting success.

A policy or environment change needs only the manifest, and takes no rebuild:

```console
$ DRY_RUN=1 rake deploy:apply   # validate against the API server first
$ rake deploy:apply
$ kubectl -n "$AIVAN_NS" rollout restart deployment/aivan-authz
```

`deploy:apply` refuses to run when a Secret the manifest mounts is missing
(`aivan-authz-db`). That is a refusal rather than a warning because the apply
would otherwise succeed and leave the pod pending on a volume. The
`kubectl create secret` command is in `deploy/k8s.yaml`'s header.

The purge CronJob is not in this manifest. It belongs to aivan-hud's chart,
because that project owns schema authz and its role is the one that can reach
the two tables without a second credential:

```console
$ helm -n "$AIVAN_NS" upgrade aivan-hud aivan-hud/k8s
```

It runs as `aivan_core` with `DELETE` plus a column-level `SELECT` on the two
predicate columns. The grant is
`aivan-hud/db/migration/202611150100_authz_purge_grants.rb`, so `rake db:migrate`
in that project has to have run before the CronJob's first pass succeeds.
`aivan-hud/k8s/values.yaml` has `purge.enabled` and `purge.suspended` if the
schedule needs to wait for the migration.

This used to be a CronJob in `deploy/k8s.yaml` running as `aivan_migrations`,
the schema owner. `aivan-hud/doc/schema-ownership.md` §3 says that role is
"never a running pod"; the move is what makes that true.

---

## 5. Rotate the database credential

The gate's credential is `aivan_authz`, created by `deploy/roles.sql`. The authz
grants are described by aivan-hud's grant migration
(`db/migration/202611140500_authz_grants.rb` and the migration that follows it).
Rotating it is three steps and one restart.

```console
# 1. A new password for the existing role. The grants follow the role name, so
#    there is nothing to re-grant.
$ kubectl -n aivan-core exec aivan-core-1 -- psql -U postgres -d aivan_core -c \
    "alter role aivan_authz password '<new-pw>'"

# 2. The secret.
$ kubectl -n "$AIVAN_NS" create secret generic aivan-authz-db \
    --from-literal AIVAN_DB_URL='postgres://aivan_authz:<new-pw>@aivan-core-rw.aivan-core.svc.cluster.local:5432/aivan_core?sslmode=require' \
    --dry-run=client -o yaml | kubectl apply -f -

# 3. Restart, which is what makes the pod read the new secret.
$ kubectl -n "$AIVAN_NS" rollout restart deploy/aivan-authz
$ kubectl -n "$AIVAN_NS" rollout status deploy/aivan-authz
```

To move to a differently *named* role, run `deploy/roles.sql` with the new name
and then re-run hud's `rake db:migrate` as the migration role: the grant
migration re-describes the whole matrix on every run, which is what makes it the
repair path for a new grantee as well as for a drifted grant.

The pod reads the secret at start, not per request, so the restart is required.

### Recognising a privilege refusal as configuration

The gate probes its credential before it opens the listener. A role that holds
more than the matrix allows is a refusal, and the pod enters
`CrashLoopBackOff`. That is the design, not a bug:

```console
$ kubectl -n "$AIVAN_NS" logs deploy/aivan-authz --previous
refusing to start: database role can create objects in schema public.
The service must run as aivan_authz with only the grants in
aivan-hud/doc/schema-ownership.md §4 (rake db:check_grants verifies them).
```

```text
refusing to start: database role can read authz.audit_log.
The service must run as aivan_authz with only the grants in
aivan-hud/doc/schema-ownership.md §4 (rake db:check_grants verifies them).
```

```text
refusing to start: database role can insert into authz.devices.
The service must run as aivan_authz with only the grants in
aivan-hud/doc/schema-ownership.md §4 (rake db:check_grants verifies them).
```

The message names the offending privilege, so the fix is a `revoke`, not a change
to the gate. `rake db:check_grants` in aivan-hud lists every line of the matrix
and is the reliable way to find what drifted.

A refusal that names `rake db:migrate` instead is a different problem: the schema
is missing, so the migrations have not run against this database.

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
revokes, and the operator commands' own actions.

**The gate cannot read this table.** It holds `INSERT` and no `SELECT`, so the
evidence is append-only to the process that writes it: a compromised gate cannot
scrub the record of its own decisions. The queries below are for a person with
the application credential or `kubectl exec`, and they are the only way to read
it.

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

`kubectl delete -f aivan-hud/deploy/routing.yaml` is **not** the way to do this.
The file's objects name `namespace: ${AIVAN_NS}`, which is not a namespace, so
`-n` refuses the file ("the namespace from the provided object ... does not
match") and no `-n` deletes into a namespace literally named `${AIVAN_NS}`.
Name the objects instead:

```console
$ kubectl -n "$AIVAN_NS" delete ingressroute aivan-hud-gate aivan-hud-gated aivan-hud-public \
    middleware aivan-auth --ignore-not-found
$ kubectl -n "$AIVAN_NS" get ingressroute,middleware
No resources found in hermes-agent namespace.
```

**Before deleting, render the router the rollback depends on.** With the three
routers gone the host has no router at all, and the chart's Ingress is off in
`k8s/values.yaml`, so `https://aivan-hud.home.arpa/` answers 404. Turn it on
first, from the hud checkout:

```console
$ helm -n "$AIVAN_NS" upgrade aivan-hud ./k8s -f k8s/values.yaml \
    --set ingress.enabled=true --set ingress.hostname="$HUD_HOST" --wait
```

`helm template ./k8s --set ingress.enabled=true` renders exactly one `Ingress`
named `aivan-hud-aivan-hud`, TLS secret `aivan-hud-tls`, all paths to
`aivan-hud-aivan-hud:4700`. Never leave `ingress.enabled=true` once the routers
are back: two routers for one host race.

Confirm the host is served again, and that `/admin` is hud's own refusal rather
than a 404:

```console
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/
200
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
401
```

The `200` is hud with no gate in front. The `401` is hud's own `require_admin!`
answering "not signed in": hud's cookie login is a form at `/login`, and a
browser that signs in there reaches `/admin` with `200`. A `404` on either line
means the host has no router at all, which is what deleting the routers without
the chart Ingress first gives you. The gate's Service can stay deployed and
unused, or be scaled to zero; with no router naming it, nothing calls it.

**Scaling the gate to zero is not free.** hud verifies every approval through
`AIVAN_GATE_URL`, so with the gate down every approval answers `503` rather
than `401`. Removing the routers does not affect that path: hud dials the
gate's cluster Service directly and never went through them.

To put the gate back, run the routing task from the hud checkout. It
substitutes `AIVAN_NS`, `HUD_SVC` and `HUD_HOST` in Ruby and removes the
chart's Ingress in the same step:

```console
$ AIVAN_NS=hermes-agent HUD_HOST=aivan-hud.home.arpa rake deploy:routing
$ kubectl -n "$AIVAN_NS" get ingressroute,middleware
```

Three `IngressRoute` objects (`aivan-hud-gate`, `aivan-hud-gated`,
`aivan-hud-public`) and one `Middleware` (`aivan-auth`). Then:

```console
$ curl -sk -o /dev/null -w '%{http_code}\n' https://aivan-hud.home.arpa/admin
401
```

Do not restore with a bare `envsubst < aivan-hud/deploy/routing.yaml`. The
three variables are usually unset in the operator's shell, so `envsubst`
renders `Host(``)` in all three routers, which matches no host and leaves the
install answering 404 — the restore appears to succeed and changes nothing. If
`envsubst` is used at all, the exports must be on the same command:

```console
$ export AIVAN_NS=hermes-agent HUD_SVC=aivan-hud-aivan-hud HUD_HOST=aivan-hud.home.arpa
$ envsubst < aivan-hud/deploy/routing.yaml | kubectl apply -f -
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
`authz-admin revoke --device <id>` stops the session on its next request, with no
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
