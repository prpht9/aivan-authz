# Putting an application behind the gate

Status: **instruction** for the owner of any application that `aivan-authz`
protects. It is written so that application can be wired up without reading
this repository's Go code. `doc/aivan-initial-spec.md` says why the service is
shaped this way; this page says what to type.

Read §1 to know what you are getting, §2–§5 to write the policy, §6 to copy a
working example, §7–§10 for the parts that are not the policy file, and §12 as
the checklist before you apply anything.

---

## 1. What the gate decides, and what your application receives

Traefik calls `/__aivan/verify` before it forwards a gated request. The endpoint
accepts every method, because the real one is in `X-Forwarded-Method` and is
covered by the signature. The gate answers with a status:

| Answer | Meaning |
|---|---|
| `200` | allowed. The identity headers below are on the response, and Traefik copies them onto the request your application sees |
| `401` | no valid proof and no valid session. The body is constant |
| `403` | a valid proof and insufficient authority, an unknown host, a plaintext arrival, or a CSRF failure |
| `302` | an HTML navigation with no proof; `Location: /__aivan/login?rd=<target>`. An older gate redirects to `/__aivan/enroll` (§11) |
| `413` | the body exceeded the gate's limit |
| `429` | too many nonce requests from one address |
| `503` | the gate could not decide (database) |

Your application only ever receives allowed requests, plus whatever Traefik
answers on its own when the gate is unreachable (`500`).

On an allow, the gate sets these response headers and Traefik passes them on
because the middleware's `authResponseHeadersRegex` is `^X-Aivan-`:

| Header | Value |
|---|---|
| `X-Aivan-User-Id` | the person's id. The only value identity should key off |
| `X-Aivan-User` | username, for logs |
| `X-Aivan-Device-Id` | the device that proved possession |
| `X-Aivan-Device-Kind` | `phone`, `tablet` or `browser` |
| `X-Aivan-Roles` | comma-separated group names, sorted |
| `X-Aivan-Proof` | how the request proved itself: `nonce` or `session` today (`mtls` is reserved in the spec and not yet produced) |
| `X-Aivan-Request-Id` | the gate's id for the request; join your errors to it |

Two headers are deliberately absent, and you must not depend on them:

- `X-Aivan-Session` is never sent. The session token is a bearer credential and
  your application must not hold it.
- No identity header is set on a denial or a redirect. Absent means "no
  identity", and on a public route it is absent by design (§5).

`X-Aivan-Request-Id` is the exception: the gate sets it on **every** response,
including a `401` and the `302` to the login page, because its job is to let an
operator join a report to a decision.

The gate is an authorization gate at the granularity of **host and path
prefix**. It does not know your objects. Object-level authorization — "may this
person edit this record" — stays in your application, using `X-Aivan-User-Id`
and `X-Aivan-Roles`.

---

## 2. The two edits, and who applies them

A new application needs two things changed outside its own repository.

**a. The gate's environment.** `AIVAN_HOSTS` is the list of hostnames the gate
will decide for. A request for a host that is not in it is a `403 host_unknown`.
It is set in the gate's Deployment (`deploy/k8s.yaml`, `env:`), for example:

```yaml
- name: AIVAN_HOSTS
  value: aivan-hud.home.arpa,notes.home.arpa
```

**b. The gate's policy ConfigMap.** The route table for every host, mounted at
`/etc/aivan/policy.yaml`. `deploy/k8s.yaml` carries it as
`ConfigMap/aivan-authz-policy`, key `policy.yaml`.

The two are cross-checked at boot: a policy that names a host missing from
`AIVAN_HOSTS` is a refusal to start, not a warning. Both edits are applied to
the gate's namespace; the gate is a single Deployment and serves every host.

Nothing else about the gate changes per application. There is no per-app
credential, no per-app database row, and no restart of anything but the gate
(§11).

---

## 3. The policy file

The whole schema is five keys. Unknown keys are refused at startup, so a typo
fails loudly rather than being ignored.

```yaml
maxBody: 2097152          # optional; see §3.1

hosts:
  notes.home.arpa:        # one entry per hostname in AIVAN_HOSTS
    scheme: https         # optional; https is the only accepted value
    routes:
      - { prefix: /__aivan/enroll, class: enrollment }
      - { prefix: /admin,          class: admin }
      - { prefix: /api,            class: authenticated }
      # A route only some devices may reach. See §3.3.
      - { prefix: /vault,          class: confidential, kinds: [phone, tablet] }
      - { prefix: /,               class: authenticated }
```

### 3.1 `maxBody`

The body ceiling the proxy in front of the gate is configured with, in the same
file as the routes so the two numbers sit together. It is optional; an absent
value means the file makes no claim.

It must be **above** the gate's own `AIVAN_MAX_BODY` (1048576 in the shipped
manifest). At or below it, Traefik would answer a too-large body first with its
own `401` and the operator would learn nothing. The gate refuses to start
otherwise. Keep this number equal to `forwardAuth.maxBodySize` in your
Middleware (§7).

### 3.2 `hosts`

One entry per hostname. The key must be a bare hostname: lowercase letters,
digits, hyphens and dots, no scheme, no port, no path, no wildcard. A wildcard
in `AIVAN_HOSTS` is refused, and a host that is not a bare hostname in the
policy is refused.

`scheme` defaults to `https` and `http` is refused. Every configured host is
https because the canonical string the client signs includes the scheme, and a
plaintext arrival is a `403 plain_http` before any signature work happens.

### 3.3 `routes`

Each route is a `prefix` and a `class`, plus `kinds` where the class needs one.
The prefix must start with `/`. Declare it without a trailing slash: matching is
whole-segment (§4.2), and `/api/` would not match `/api/x`.

| Class | What it requires | Refusal |
|---|---|---|
| `public` | nothing; no identity headers are set | — |
| `authenticated` | any active device of an active user, by proof or by session cookie | `401`, or `302` for an HTML navigation |
| `admin` | the same, plus membership in the `admin` group | `403 role_insufficient` |
| `confidential` | the same, **and** a device whose kind is in the route's `kinds` | `403 device_kind_insufficient` (or `401` with no device) |
| `enrollment` | a body carrying a signed pending-enrollment claim. Valid **only** on `/__aivan/enroll` | `403` |

`enrollment` is pinned to one prefix by construction: the class accepts a body
with no user proof, so a second use of it would be a second unauthenticated
write path. Declaring it anywhere else is a refusal to start.

#### `kinds`

`kinds` is a list drawn from the five device kinds the schema has — `phone`,
`tablet`, `browser`, `panel`, `tv` — and it is **required on `confidential` and
refused everywhere else.** The reason it is refused elsewhere:

- `public` and `enrollment` have no identity, so there is no kind to check. A
  `kinds` there would look like a restriction that nothing enforces.
- `authenticated` and `admin` are meant to accept any device. Putting a list on
  one would be a second way to spell `confidential`, and `admin` narrowed to one
  kind locks an operator out of their own console with a change that reads as
  unrelated.
- `confidential` **with an empty list** is refused: it would be `authenticated`
  under a second name.

The word `confidential` is also a *level* in the authorization model, where it
means rank 4. They are different things and no route class is a level: a class
says which device may reach a path, a level says how much a grant is worth.

```yaml
routes:
  - { prefix: /vault, class: confidential, kinds: [phone, tablet] }
```

With that route, a browser proof is `403` and the decision log carries
`reason: device_kind_insufficient`; a phone or tablet proof is `200`. The same
browser is `200` on `authenticated` routes, so the refusal is the route.

**The shipped policy does not use it.** `deploy/k8s.yaml` keeps its three routes
with no `kinds`, because narrowing `/admin` to a phone before a phone is enrolled
on the install is a lockout, and that is a separate decision.

#### The device kinds, and the `pending` state

A device row has a `state` of `pending`, `live` or `revoked`. Only a `live`
device is decided for: a pending one is refused on every path with
`reason: device_pending`, which an operator can tell apart from
`device_revoked` and from a bad key. `authz-admin list-devices` shows a `STATE`
column, and `authz.promote_device()` is the one way a row leaves `pending`.

Every host that will serve enrollment needs the `enrollment` route on
`/__aivan/enroll`. Without it, `POST /__aivan/enroll` on that host answers `403`
with an empty body, the gate logs the note
`host policy does not classify /__aivan/enroll as enrollment`, and no phone or
browser can enrol against that origin.

---

## 4. How a path is matched

### 4.1 Longest prefix wins

Routes are sorted longest-prefix-first at startup, so declaration order in the
file does not matter. `/admin/audit` beats `/admin`, which beats `/`.

### 4.2 Prefixes match whole segments

A prefix matches the exact path, or a path that continues with `/`:

| Prefix | Matches | Does not match |
|---|---|---|
| `/api` | `/api`, `/api/`, `/api/v1/x` | `/apifoo` |

The query string is stripped before matching, so `/admin?tab=users` is decided
by `/admin`.

### 4.3 An uncovered path is `authenticated`, and logged

A path with no matching prefix is not public. It is classified
`authenticated` with `reason: class_defaulted`, and the gate logs a warning
naming the host and target. That is deliberate: an uncovered path served as
public is a silent open door, while a visible `401` is fixed by editing the
file.

Treat every `class_defaulted` line in the gate's log as a missing route.

### 4.4 One prefix, one class

Two routes with the same prefix on one host are refused at startup. An
arbitrary order for an authorization decision is a bug waiting for a quiet
deployment.

### 4.5 What a bad file does

The gate refuses to start. It never serves a partially loaded table.

| Refusal names | Cause |
|---|---|
| `AIVAN_HOSTS is required and must list at least one host` | the env var is empty |
| `AIVAN_HOSTS entry "..." is a wildcard; list hosts explicitly` | `*.home.arpa` |
| `AIVAN_HOSTS entry "..." must be a bare hostname` | scheme, port or path in the env list |
| `policy host "..." is not listed in AIVAN_HOSTS` | the two edits disagree |
| `policy maxBody (...) is not above AIVAN_MAX_BODY (...)` | §3.1 |
| `hosts is empty` | no hosts key |
| `host "..." is not a bare hostname` | scheme, port or path in the policy key |
| `uses scheme "..."; only https is allowed` | §3.2 |
| `has prefix "..."; prefixes start with /` | the prefix does not start with `/` |
| `uses unknown class "..."` / `has a route with no class` | not one of the five in §3.3 |
| `declares class "enrollment" on "...", which is not /__aivan/enroll` | §3.3 |
| `names device kind "..."; the kinds are ...` | §3.3, a typo in `kinds` |
| `names device kind "..." twice` | §3.3, `kinds: [phone, phone]` |
| `is class "confidential" with no kinds` | §3.3, otherwise `authenticated` under a second name |
| `is class "...", which has no device identity to check; kinds belongs on "confidential"` | §3.3, `kinds` on `public` / `enrollment` |
| `is class "..." and names kinds; only "confidential" requires them` | §3.3, `kinds` on `authenticated` / `admin` |
| `has prefix "..." more than once` | §4.4 |
| `yaml: unmarshal errors` / `field ... not found` | a key the schema does not have |

---

## 5. `public` is a routing decision, not a policy entry

This is the one part of the policy that is easy to get wrong.

A public route is served by a Traefik router that **does not pass through
`forwardAuth` at all** (§7). It therefore never reaches the gate, and the
`public` class exists for the opposite case: a path that arrived through the
gated router despite being public. When that happens the gate answers `200`, sets
no identity headers, and logs `reason: public_route`, because the routing is
wrong.

So when you add a public path you add it in two places:

1. the public `IngressRoute`'s rule (§7), so it bypasses the gate, and
2. optionally, the policy as `class: public`, so a routing regression is visible
   in the gate's log.

The policy entry is a diagnostic, not a gate. A path listed as `public` in the
policy but missing from the public router still reaches the application, still
gets a `200`, and still carries no identity headers — the only difference is the
gate's warning line. What breaks is the opposite: a path that is public in the
router but absent from the policy never touches the gate, so nothing is wrong
and nothing is logged.

The failure mode that bites is the common one: **a route added to your
application and not added to the public router lands on the gated catch-all and
starts requiring a device.** If a page suddenly asks for enrolment after a
deploy, this is why.

---

## 6. A complete example for a new application

`notes.home.arpa`, a Sinatra-shaped app on port 4700, in namespace `notes`,
with a login-free index and an admin section.

**Gate environment** (edit the gate's Deployment):

```yaml
- name: AIVAN_HOSTS
  value: aivan-hud.home.arpa,notes.home.arpa
```

**Gate policy ConfigMap:**

```yaml
maxBody: 2097152

hosts:
  notes.home.arpa:
    routes:
      - { prefix: /__aivan/enroll, class: enrollment }
      - { prefix: /admin,          class: admin }
      - { prefix: /,               class: authenticated }
```

**Your Middleware** — identical for every application except the namespace:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: aivan-auth
  namespace: notes
spec:
  forwardAuth:
    address: "http://aivan-authz.notes.svc.cluster.local:8080/__aivan/verify"
    trustForwardHeader: false
    authResponseHeadersRegex: "^X-Aivan-"
    authRequestHeaders:
      - "X-Aivan-Device"
      - "X-Aivan-Nonce"
      - "X-Aivan-Signature"
      - "X-Aivan-Timestamp"
      - "Cookie"
      - "X-Aivan-Csrf"
      - "Accept"
    preserveRequestMethod: true
    forwardBody: true
    maxBodySize: 2097152
    preserveLocationHeader: true
```

**Three IngressRoutes on your host**, in this shape: the gate's own surface, the
public list, and the gated catch-all.

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: notes-gate, namespace: notes }
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`notes.home.arpa`) && PathPrefix(`/__aivan/`)
      kind: Rule
      services: [{ name: aivan-authz, port: 8080 }]
  tls: { secretName: notes-tls }
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: notes-public, namespace: notes }
spec:
  entryPoints: [websecure]
  routes:
    - match: >-
        Host(`notes.home.arpa`) && (Path(`/`) || Path(`/index.html`) || Path(`/style.css`) || Path(`/login`) || Path(`/register`))
      kind: Rule
      services: [{ name: notes, port: 4700 }]
  tls: { secretName: notes-tls }
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: notes-gated, namespace: notes }
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`notes.home.arpa`)
      kind: Rule
      middlewares: [{ name: aivan-auth }]
      services: [{ name: notes, port: 4700 }]
  tls: { secretName: notes-tls }
```

Traefik evaluates longer rules first, so the two specific routers win over the
catch-all without an explicit priority. Keep the public rule on one line:
Traefik's rule parser refuses a newline inside parentheses.

---

## 7. The Traefik side, field by field

Every field below is load-bearing, and each was observed on Traefik 3.7.13
(`doc/traefik-contract.md`).

| Field | Why |
|---|---|
| `address` | the gate's **cluster Service**, never an ingress host: a call through an ingress router could recurse |
| `trustForwardHeader: false` | the gate must see Traefik's own forwarded headers, not a client's |
| `authResponseHeadersRegex: "^X-Aivan-"` | strips client-supplied `X-Aivan-*` before setting the gate's values. Anchored on purpose |
| `authRequestHeaders` | exactly the four proof headers, `Cookie`, `X-Aivan-Csrf` and `Accept`. Never an identity header — Traefik does not strip matching headers from the request it sends to the auth service |
| `preserveRequestMethod: true` | the method is covered by the signature |
| `forwardBody: true` | the body hash is covered by the signature |
| `maxBodySize` | the hard ceiling above the gate's own limit (§3.1) |
| `preserveLocationHeader: true` | without it the gate's relative `302` is rewritten to an absolute URL on the gate's cluster address |

`Accept` is in the list because Traefik does not forward it unless named, and
the gate reads it to choose between a `302` for a browser navigation and the
constant `401` body. It is not identity; it only chooses the denial shape.

Two deployment constraints:

- **The gate's Service must be in the same namespace as your IngressRoutes.**
  Traefik refuses a Service in another namespace than the parent resource
  (`service notes/aivan-authz not in the parent resource namespace aivan`), and
  that applies to the `services:` block of every router — including the
  `/__aivan/` router. So an application in a new namespace needs the gate
  deployed there too, or the application joins the namespace the gate already
  serves. The Middleware's `address` is a plain URL that Traefik dials, so it
  may cross namespaces; the routers may not.
- **`/__aivan/` must be routed to the gate on your host, with no middleware.**
  That router carries the session mint (`POST /__aivan/session`), the login
  page, the enrolment page and the approvals verifier. A `302` to
  `/__aivan/login` that reaches your application instead is a `404` the user
  reads as a broken login.

---

## 8. What your application must do with the headers

**Read `X-Aivan-User-Id` and nothing else for identity.** A request with no
`X-Aivan-User-Id` has no identity. Build your identity object from the header
set in §1 and never from a client-supplied value: the only reason the header can
be trusted is that `authResponseHeadersRegex` removed any incoming copy before
Traefik set the gate's.

`X-Aivan-Roles` is the comma-separated group list, sorted. Split on `,` and
reject empty strings. Treat it as the gate's statement of the roles held at the
moment of the request — roles are resolved per request, so a revoked role is
gone on the next one.

`X-Aivan-User` is for logs. `X-Aivan-User-Id` is what your foreign keys use, and
a username change must not move them.

`X-Aivan-Request-Id` is not a secret. Put it in your error responses so an
operator can join a user's report to a gate decision.

Two habits that matter:

**Do not set an `X-Aivan-*` header yourself.** It would be stripped on the way
in, so it achieves nothing, and a habit of setting them invites an application
that reads them from a path the gate does not guard.

A public route carries no identity headers at all. If your application supports
both public and gated views of the same page, decide from the absence of
`X-Aivan-User-Id`, not from a cookie of your own.

---

## 9. Sessions, and the CSRF header

Your application does not issue the session cookie. The gate does, and it is
named `__Host-aivan_session`: `Secure`, `Path=/`, `HttpOnly`, `SameSite=Lax`, no
`Domain`. The `__Host-` prefix is what keeps it off sibling subdomains.

Your own JavaScript mints one by signing a proof and posting it:

| Request | Effect |
|---|---|
| `POST /__aivan/session` | exchange a signed proof for the cookie. `204` on success |
| `DELETE /__aivan/session` | log out. Deletes the row and clears the cookie |

The proof must cover `POST /__aivan/session` as its target. A proof captured for
an application route cannot be replayed here, and a mint cannot be replayed as
an application request.

Once a browser holds the cookie, a state-changing request needs one of:

- `Sec-Fetch-Site: same-origin` or `none` — what a modern browser sends for your
  own fetch calls, so most applications need nothing, or
- a header `X-Aivan-Csrf: <token>` where the token matches
  `^[A-Za-z0-9_-]{16,128}$`. The value is not compared to anything; it is a
  presence test a cross-origin HTML form cannot satisfy.

`same-site` is refused even with the header: it spans sibling subdomains, which
is not the boundary the `__Host-` cookie draws.

A request that carries any of the four proof headers is on the proof path and
does not need the CSRF header — the signature covers the method, target and
body. So a non-browser client (a service, a phone) signs; a browser with a
cookie sends the header.

Your application must not strip `Cookie`, `X-Aivan-Csrf` or `Accept` before the
gate sees them, and must not set a cookie of the same name. Because the cookie is
`__Host-`, your application cannot shadow it even deliberately: a `__Host-`
cookie needs `Secure`, `Path=/` and no `Domain`, and a duplicate on a different
path is refused by the browser.

The `Cookie` header is on the Middleware's `authRequestHeaders` list, so the gate
sees it. Nothing else in your application needs to change for a cookie to work:
`/__aivan/session` is on the gate's own router, so the `Set-Cookie` arrives at
the browser as an ordinary proxied response.

---

## 10. Enrolling a device for a new origin

A device row is bound to one origin. A key enrolled for `aivan-hud.home.arpa`
will not authenticate `notes.home.arpa`, and the session row is keyed by origin
too, so a cookie minted on one host is refused on the other.

Each new host therefore needs its own enrolment:

```console
$ ./bin/authz-admin enroll-new --username alice --origin notes.home.arpa --kind browser
```

That prints a code once, and at a terminal also a QR square encoding
`https://notes.home.arpa/__aivan/enroll?code=<code>`. The phone or browser
completes the claim against the gate, and `POST /__aivan/enroll` needs the
`enrollment` class on that host (§3.3).

`doc/enrollment-qr.md` is the contract for a mobile app doing this.

---

## 11. Applying a change, and verifying it

The policy file is read once at boot. There is no reload and no watch: editing
the ConfigMap does nothing until the gate restarts.

```console
$ kubectl -n "$NS" edit configmap aivan-authz-policy
$ kubectl -n "$NS" rollout restart deploy/aivan-authz
$ kubectl -n "$NS" rollout status  deploy/aivan-authz
```

**A `kinds` change is a rollout restart, always.** There is no reload: the file is
read once, in `Load`, before the listener opens (§3.3 and `config.go`). Editing
the ConfigMap and reloading a page changes nothing, and the old table keeps
deciding until the pod restarts.

A bad file shows as `CrashLoopBackOff` with the refusal on stderr. That is the
gate working as intended — it will not serve a table it could not build. Read it
with:

```console
$ kubectl -n "$NS" logs deploy/aivan-authz --previous
```

Then verify, from outside the cluster:

```console
$ curl -sk -o /dev/null -w '%{http_code}\n' https://notes.home.arpa/         # 200, public
$ curl -sk -o /dev/null -w '%{http_code}\n' https://notes.home.arpa/admin    # 401, gated
$ curl -sk -D- -o /dev/null https://notes.home.arpa/admin | grep -i x-aivan  # only X-Aivan-Request-Id
```

With a browser that holds a key, the same `/admin` should return `200` and your
application should log an `X-Aivan-User-Id`. A `302` to
`/__aivan/login?rd=/admin` is the gate telling an unenrolled browser where to
go, and a `404` on that follow-up means `/__aivan/` is not routed to the gate on
your host (§7).

The redirect target depends on the gate version: a gate built before the login
page landed sends the browser to `/__aivan/enroll` instead. If you see that, the
running image is older than this document — check it before you conclude the
policy is wrong.

### Reading a status

| Status | Produced by | What to check |
|---|---|---|
| `401` | gate | the decision log's `reason`: `no_proof`, `session_invalid`, `nonce_unknown`, `bad_signature`, `timestamp_skewed`, `device_revoked`, `device_pending` (waiting for approval) |
| `403` | gate | `role_insufficient` (policy is right, the person lacks the role), `device_kind_insufficient` (a confidential route refused this device's kind), `host_unknown` (host missing from `AIVAN_HOSTS` or the policy), `plain_http` (a router is missing `tls:`), `csrf_missing` / `csrf_samesite` |
| `404` | your application | the gate allowed it; the route does not exist, or `/__aivan/` is not routed to the gate |
| `413` | gate | the body is above `AIVAN_MAX_BODY` |
| `429` | gate | nonce rate limit |
| `500` | Traefik | the gate is unreachable; `forwardAuth` has no other way to fail closed |
| `503` | gate | the database, or the nonce table at its cap |

Decisions are JSON on the gate's stdout at `info`, one line per request, with
`decision`, `status`, and `reason` on a denial. They carry no signature, nonce,
cookie or key.

`doc/runbook.md` has the full reason-code table and the failure drills.

---

## 12. Checklist

Before you apply:

- [ ] Every hostname is in `AIVAN_HOSTS` and in the policy's `hosts` map, spelled the same.
- [ ] Each host has `/__aivan/enroll` as `class: enrollment` if anyone will enrol there.
- [ ] Every prefix your application serves is declared; declaration order does not matter, but longest-first reads better.
- [ ] Every `confidential` route names its `kinds`, and no other class names any (§3.3).
- [ ] The `/` route exists as `authenticated`, so nothing is left to default.
- [ ] `maxBody` is above the gate's `AIVAN_MAX_BODY`, and equal to `maxBodySize`.
- [ ] The Middleware lists only the four proof headers, `Cookie`, `X-Aivan-Csrf` and `Accept`.
- [ ] The `/__aivan/` router points at the gate Service, in the same namespace, with no middleware.
- [ ] The public router lists every path your application serves without identity.
- [ ] The gated router is the catch-all on the host.
- [ ] Your application reads `X-Aivan-User-Id` and treats its absence as no identity.
- [ ] Your application serves nothing under `/__aivan/`.
- [ ] A device is enrolled for the new origin.

After you apply:

- [ ] `curl` on a public path returns `200`.
- [ ] `curl` on a gated path returns `401`, with `X-Aivan-Request-Id` and no identity header.
- [ ] A browser with a key reaches the gated path and your log shows the user id.
- [ ] The gate's log has no `class_defaulted` line for your host.
