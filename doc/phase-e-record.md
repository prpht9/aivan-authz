# Phase E — verification record

Date: 2026-11-13. Cluster: k3s v1.36.5+k3s1, single node (server01),
Traefik 3.7.13, PostgreSQL 14.5 via CloudNativePG. Recorded so Phase F does not
have to re-derive it.

## What was built

| Plan item | Where |
|---|---|
| E1 two repositories | `ce361f2` in `aivan-authz`, `6ae58a5` in `aivan-hud` |
| E2 three routers | `aivan-hud/deploy/routing.yaml` (Middleware + 3 IngressRoutes) |
| E3 header identity | `aivan-hud/app.rb` (`gateway_identity`, `current_user`, `require_admin!`) |
| E4 logging | `aivan-hud/app.rb` (`before` block, `denial_body`) |
| E5 gate deployment | `aivan-authz/deploy/k8s.yaml`, `aivan-authz/deploy/roles.sql` |
| E6 testing without enrollment | `aivan-authz/internal/console/devsession.go`, `cmd/authz/devtools.go` |
| chart change | `aivan-hud/k8s/values.yaml` (`ingress.enabled`), `k8s/templates/ingress.yaml` |

Files outside the new code: `cmd/authz/main.go` gains `extraCommands` so a
build-tagged subcommand registers itself and the shipped binary contains none;
`internal/gate/session.go` exports `SessionCookieHeader` so the console mint and
the endpoint write the same cookie; `internal/config/config.go` exports
`ParseHosts` so the console validates `--origin` against the same list the gate
serves.

## Where the plan was wrong, and what was done instead

### 1. The routers cannot live in a different namespace from the application

The plan puts the three routers and the gate in `aivan`, next to hud. On this
cluster hud runs in `hermes-agent`, and Traefik refuses a cross-namespace
reference:

```console
$ kubectl -n aivan get ingressroute xns-probe
$ curl -sk --resolve xns-probe.home.arpa:443:192.168.192.2 https://xns-probe.home.arpa/
404

$ kubectl -n kube-system logs deploy/traefik | grep xns-probe
ERR error="service hermes-agent/aivan-hud-aivan-hud not in the parent resource namespace aivan"
    ingress=xns-probe namespace=aivan providerName=kubernetescrd
```

So the gate, the middleware and the routers were deployed into `hermes-agent`
alongside hud. `deploy/k8s.yaml` and `deploy/routing.yaml` both take the
namespace from `AIVAN_NS`; moving either service later is one `envsubst` and
one re-apply, with the two together.

### 2. The public rule cannot contain a newline inside its parentheses

The plan's YAML block wraps the path list across lines. Traefik's rule parser
rejects it:

```console
ERR error="error while parsing rule Host(`aivan-hud.home.arpa`) && (\n  Path(`/`) || …):
    8:56: expected ')', found newline"
```

The rule is now one line. The list itself is unchanged.

### 3. `Accept` must be in `authRequestHeaders`, or acceptance 3 cannot hold

The plan's middleware list omits `Accept`, and the spec's decision matrix reads
`Accept` to choose between the constant 401 and the 302 to `/__aivan/enroll`.
Traefik forwards only the request headers it is told to, so the gate never saw
it:

```console
$ curl -sk -H 'Accept: text/html' https://aivan-hud.home.arpa/admin
HTTP/2 401                      # before: no redirect, acceptance 3 failed
```

With `Accept` listed:

```console
$ curl -sk -D- -o /dev/null -H 'Accept: text/html' https://aivan-hud.home.arpa/admin
HTTP/2 302
location: /__aivan/enroll?rd=%2Fadmin
x-aivan-request-id: 7f265dea05be76faca910dfcd1fa8db0
```

`preserveLocationHeader: true` is what keeps `Location` relative; without it the
browser would be sent to the gate's cluster address (`doc/traefik-contract.md`).
`Accept` is not identity: it only chooses the denial shape.

### 4. PostgreSQL 14 grants `CREATE` on `public` to `PUBLIC`

The gate's boot probe refuses to start when the runtime role can create objects
in `public` (S16, S20). `0002_grants.sql` revokes the privilege from
`aivan_authz`, which is not enough on 14.5, where `PUBLIC` holds it and every
role inherits:

```console
$ psql -c "select has_schema_privilege('aivan_authz','public','CREATE')"
 t                              # after the migration's revoke
```

The install now revokes it from `PUBLIC` and grants it to the application's
owner and to `aivan_migrations`, which reproduces the PostgreSQL 15 default.
`deploy/roles.sql` carries the statements and the checks.

### 5. The gate's schema was owned by the application's role

`authz.*` was created by `aivan_core` because that is who ran the first
migration. The runtime role then held implicit rights through its owner, and a
second migrate as `aivan_migrations` was refused:

```console
$ authz migrate   # as aivan_migrations, against the fresh test database
migrate: migration 0001_init.sql: ERROR: permission denied for table users
```

Ownership moved to `aivan_migrations` and the migration role got `REFERENCES`
on `public.users` plus the same column grants `0002_grants.sql` applies, with
the grant option. The runtime role's rights are unchanged by that move and
remain the ones `0002_grants.sql` names.

## Two roles, and why

| Role | Purpose | Holds |
|---|---|---|
| `aivan_authz` | the runtime credential in the pod | `0002_grants.sql`: schema `authz` DML, `select (id, username, active)` on `users`, `select` on `groups`/`groups_users`. No `CREATE` anywhere, no `password_digest` |
| `aivan_migrations` | `authz migrate`, run from a workstation | owns schema `authz`; `CREATE` on `public`; `REFERENCES` on `users`; the three column grants `0002` re-applies, with grant option |

The verification below is the output of `select` on `pg_catalog` after both
roles existed and the migrations ran:

```console
 authz: CREATE on public      | f
 authz: password_digest       | f
 authz: users.id select       | t
 authz: users INSERT          | f
 authz: authz.devices INSERT  | t
 migrations: authz owner      | t
 migrations: public CREATE    | t
 migrations: users references | t
 core: public CREATE          | t
```

A fresh database was built as a check: `create database aivz_migtest`, the
application's three tables as `aivan_core`, the grants above, then
`authz migrate` as `aivan_migrations`:

```console
{"level":"INFO","msg":"migrations applied","versions":[1,2]}
{"level":"INFO","msg":"migrations up to date"}      # second run
```

## Checklist, with what was observed

Applied manifest (namespace `hermes-agent`, since that is where hud is):

```console
$ kubectl -n hermes-agent get ingressroute,middleware
ingressroute.traefik.io/aivan-hud-gate
ingressroute.traefik.io/aivan-hud-gated
ingressroute.traefik.io/aivan-hud-public
middleware.traefik.io/aivan-auth
```

- [x] Three routers applied and visible.
- [x] **Acceptance 3.** `/admin` with no cookie, from a browser, returns the
      redirect and hud logs nothing for it:
      ```console
      HTTP/2 302
      location: /__aivan/enroll?rd=%2Fadmin
      x-aivan-request-id: 7f265dea05be76faca910dfcd1fa8db0
      ```
      The hud log had no `/admin` line for that request. The redirect target
      itself is `404` on the gate because Phase F builds it; the routing is
      what this phase proves.
- [x] **Acceptance 4.** A forged `X-Aivan-User: attacker`, `X-Aivan-User-Id: 1`
      and `X-Aivan-Roles: admin` on `/admin` with no cookie produce the same
      `302`, not the table:
      ```console
      HTTP/2 302
      location: /__aivan/enroll?rd=%2Fadmin
      x-aivan-request-id: a8e0c4b7fd832d5293a9ae416fe7b6db
      ```
      The gate decided `no_proof`; the forged values never reached it as
      anything it reads, and hud saw no request at all.
- [x] The same forged headers with a valid cookie still yield the cookie's
      user. The page rendered `<td>chris</td>`, and the gate logged
      `user_id: 10` — the cookie's device — with the forged role ignored.
- [x] `/admin` with a console-minted cookie renders the users table:
      ```console
      HTTP/2 200
      <title>Users</title>
      <tr><th>username</th><th>email</th><th>verified</th><th>admin</th></tr>
      <tr><td>chris</td><td>…</td><td>true</td><td>true</td></tr>
      ```
      Gate decision: `"route":"/admin","user_id":"10","decision":"allow"`.
- [x] A non-admin is refused by the gate, before hud: `403`, empty body,
      `"reason":"role_insufficient"`.
- [x] `/` returns the galaxy page (125 749 bytes) with no cookie.
- [x] The viewer assets load with no cookie. These were the likeliest
      breakage:
      ```console
      /index.html        200  125749
      /hud-script.js     200   13217
      /hud-style.css     200    2477
      /graph-data.js     200 3445852
      ```
- [x] `/chat` (POST), `/speak`, `/voices`, `/profiles`, `/hold` work with no
      cookie. `POST /chat` with `{"question":"hello"}` returned `200` and a
      banter answer; `GET /chat` is `404` from Sinatra, as before.
- [x] `/login` renders (`200`) and `POST /login` with a wrong password returns
      `401` with the page's error, which means `request.ssl?` is still true
      through the new middleware hop (the HTTPS guard did not fire). The
      `hud_session` cookie alone does not open `/admin`: a cookie carrying
      `user_id=10` and a valid HMAC returned `401` with
      `authentication required: POST /__aivan/nonce`.
- [x] **Fail-closed.** With the gate scaled to zero:
      ```console
      admin code=500 time=0.013828
      root  code=200 size=125749
      graph code=200
      ```
      The gated route fails in 14 ms, below Traefik's hardcoded 30 s timeout,
      and the public surface keeps serving. Matches spec §8.2.
- [x] **Acceptance 10.** From a pod in the same namespace, with a positive
      control:
      ```console
      $ curl http://192.168.201.28:8080/healthz       # gate cluster IP
      curl: (28) Connection timed out after 8002 milliseconds
      $ curl http://aivan-authz.hermes-agent.svc.cluster.local:8080/healthz
      curl: (28) Connection timed out after 8002 milliseconds
      $ curl http://aivan-hud-aivan-hud:4700/         # control: no policy
      hud code=200
      ```
      DNS resolves and TCP is dropped, which is the NetworkPolicy. The gate has
      no `Ingress` and no `IngressRoute` of its own.
- [x] **S21.** A second gate instance served `second.home.arpa` from the same
      database. The hud session was refused there and allowed at home:
      ```console
      $ curl … -H 'X-Forwarded-Host: second.home.arpa' … /__aivan/verify
      HTTP/1.1 401 Unauthorized
      decision: "host":"second.home.arpa","decision":"deny","reason":"session_invalid"
      $ curl … -H 'X-Forwarded-Host: aivan-hud.home.arpa' … /__aivan/verify
      HTTP/1.1 200 OK
      X-Aivan-Proof: session
      decision: "host":"aivan-hud.home.arpa","route":"/admin","decision":"allow"
      ```
      The second instance was a local process against the same database, not a
      deployed host. A real second host is Phase G's; the property it tests is
      proven here.
- [x] `X-Aivan-Proof: session` appears in hud's log for a cookie request:
      ```console
      I, INFO -- : gate method=GET path=/admin request_id=a5b150f2… proof=session
      ```

## Application tests

The gate-header scenarios are in `features/001_accounts.feature` and pass with
the rest:

```console
19 scenarios (19 passed)
78 steps (78 passed)
```

The four that matter:

| Scenario | Asserts |
|---|---|
| The gate's headers reach admin without hud's own cookie | `200` and the table, with `X-Aivan-User-Id` and no cookie |
| The gate's headers reach admin with no admin role | `403` and `{"error":"not an admin"}` |
| A forged username and roles without the gate's user id do not authenticate | `401`: identity keys off the id header only |
| The gate's user id wins over hud's own cookie | a valid `operator` cookie plus `ada`'s header is `403` |

## What this phase does not prove

- **A browser can mint its own session.** Enrollment is Phase F. Every session
  here came from `authz dev-session`, and that command is the thing Phase F
  deletes.
- **A browser rendering the pages.** This host's headless Firefox cannot map a
  framebuffer (`RenderCompositorSWGL failed mapping default framebuffer`) and
  no Playwright or Puppeteer is installed, so verification used requests with
  Firefox's own navigation headers (`Accept`, `Upgrade-Insecure-Requests`,
  `Sec-Fetch-*`) and checked statuses, `Location`, content type and the
  rendered rows. The CSRF rule's `Sec-Fetch-Site: same-origin` from a real
  browser is still Phase F's end-to-end check.
- **The gate under load.** Phase G.
- **A `413` at the gate.** Phase G; the middleware's `maxBodySize` ceiling is
  in place but the one-byte-over test is not.
- **A NetworkPolicy on hud.** The pod is reachable from any pod in the cluster
  today. What keeps the gate meaningful is that hud's Service is not exposed by
  any router other than the three above. A pod-to-pod bypass of hud is a real
  gap and belongs with Phase G's hardening.

## Decisions inside the plan's latitude

- **The dev mint is a separate file behind `devtools`, registered through a
  map.** `main.go` gains `extraCommands` and `extraUsage`, both empty in the
  shipped build, so the image's `authz help` lists no dev command and Phase F
  removes two files. Verified with `docker run … /authz help`.
- **`dev-session` writes its session with the endpoint's own statement.**
  `console.MintDevSession` calls `store.SessionMintSQL`, so the row it writes is
  the row the gate reads. It generates a public key it then discards: the device
  can hold a cookie and cannot sign, which is the difference between a testing
  affordance and a credential.
- **The console refuses a repeat device.** The partial unique index would
  refuse it anyway; the error names `authz list-devices` and `authz revoke`, so
  a second test on the same origin is one command away.
- **`Accept` is the one non-credential header added to `authRequestHeaders`.**
  The alternative — always redirecting HTML and never redirecting API clients —
  needs the same header. The list stays minimal: no `User-Agent`, no
  `Referer`, no identity header.
- **The Ingress template is off by default, not deleted.** A throwaway install
  with no gate still works, and the rollback in the plan stays true.
- **hud's proof log is one line per gated request, not per request.** The
  public surface has no gate hop, so the line would be empty there; logging it
  only when a request id arrives keeps the galaxy page's log clean.

## Handoff to Phase F

Available and proven: the `/__aivan/` gate router reaches the gate from
outside, `POST /__aivan/session` is where a cookie is minted, `GET
/__aivan/enroll` is routed to the gate and returns its own 404 until the page
exists, and hud reads `X-Aivan-User-Id`/`X-Aivan-Roles` and refuses correctly.

Two things Phase F must supply that this phase could not: the enrollment page
itself, and the browser-side key. It must also delete `devsession.go`,
`devtools.go` and the `extraCommands` seam if it does not want a third
subcommand later.

For a manual test before that: `authz dev-session --username <name>` prints a
`Set-Cookie` line whose second field is exactly what `curl -b` and a browser
accept. `authz revoke --device <id>` ends it.