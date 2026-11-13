# aivan-authz — initial specification

Status: revision 2, decided. Not a plan. It states what the service must be and
what it must refuse; sequencing and file layout are in
`doc/aivan-initial-plan.md`.

Revision 2 applies the decisions taken while planning: Go, no password path in
this service, per-origin devices with host-scoped cookies, server-side sessions,
and a fixed algorithm list of Ed25519 and ES256. It also adds requirements S19
through S21, and corrects three assumptions about Traefik's `forwardAuth` that
the first revision got wrong (see §8.1).

Revision 3 applies what Phase A observed on Traefik 3.7.13
(`doc/traefik-contract.md`): `Location` needs `preserveLocationHeader`, and the
path in `X-Forwarded-Uri` is normalised by the entrypoint while the query string
is not (amendments A22 and A23).

## 1. Purpose

aivan-authz is the authentication and authorization gate in front of the AIVAN
web surface. It runs as a Traefik `forwardAuth` target: Traefik calls it before
forwarding a request to an application, and the application only ever sees
requests that aivan-authz allowed.

It answers one question per request:

> Is this request from a person and device we know, and may that person and
> device do this thing here?

It answers with an HTTP status and a small set of identity headers. It holds no
user interface, renders no pages, and stores no session of its own beyond the
nonce and device records it owns.

The first consumer is aivan-hud. The design assumes more consumers, because
access grants are the product's purpose, and a second application must be able
to reuse the same gate without a second identity system.

## 2. Scope of this document

In scope: what the service is, the authentication mechanisms it accepts,
the authorization decision it returns, the data it owns, the security
properties it must hold, and the operational contract with Traefik.

Out of scope here: migration plan, module layout, deployment manifests beyond
the contract they must satisfy, disaster recovery, and the design of the phone
approval interface. Those belong in later documents.

## 3. Context and prior art

`van-auth`, linked in this repository, is the predecessor. It is a Rack app
that accepts credentials over HTTP Basic or a JSON POST and returns:

```
200 with X-Remote-User and X-Remote-Roles
401 otherwise
```

It was deployed behind Emissary (Ambassador) `AuthService`, with
`X-Remote-User` and `X-Remote-Roles` in `allowed_authorization_headers`, a
5000 ms timeout, `status_on_error: 403`, and `failure_mode_allow: false`. It
performed well under load with Ruby and Postgres.

That is the right shape and the right failure posture. This specification keeps
both. What changes:

| van-auth | aivan-authz |
|---|---|
| Shared password | Device keypair proof, nonce-bound |
| Password as a stored digest | No password reachable by this service at all |
| `X-Remote-*` headers | `X-Aivan-*` headers, anchored regex, stripped before set |
| One role list from a JSONB column | Roles from groups, resolution defined per host and route |
| Emissary `AuthService` | Traefik `forwardAuth` middleware |
| Global policy | Per-host, per-route policy |
| No replay protection | Single-use server nonces, bound to request |

The language is Go 1.26. See section 12.

## 4. Trust model

Trust boundaries, in the order they matter:

1. **The verifier is the compute server.** Device records and the code that
   accepts or rejects a device proof live on the same host as the database.
   Anyone who owns that host can forge a device row. No client-certificate
   authority can protect against that, so aivan-authz does not pretend to.
2. **The phone's private key is the strongest credential in the system.** It
   lives in a secure enclave, is non-exportable, and is unlocked by the user's
   biometry.
3. **A browser's device key is weaker.** A WebCrypto key can be non-extractable
   and profile-bound, which is good, but the browser and the OS are a larger
   attack surface than a phone enclave. It is also **origin-scoped**: a
   non-extractable key created on one host cannot be used from another. Device
   records are therefore scoped per origin, and a person with three applications
   has three browser devices. See amendment A13.
4. **A pending enrollment code is the weakest credential, and it is single-use
   and short-lived.** It names a person and permits one device to be bound to
   them, and it is consumed by the claim it authorizes. There is no password in
   this service to rank at all (amendment A12).
5. **Traefik is trusted to set headers and to call this service.** The
   application trusts `X-Aivan-*` headers because Traefik strips any incoming
   header matching that pattern before setting the ones this service returns.

The service must never assume a header it did not set. The application must
never trust an `X-Aivan-*` header it could receive from any other source, which
is why those applications must be reachable only through Traefik.

## 5. Authentication

Two mechanisms, one concept: a **device proof**. Both resolve to the same
`devices` row and the same identity headers. A user has many devices; there is
no fixed cap.

### 5.1 Signed nonce (primary)

The client holds a private key it generated locally. It never leaves the device
where the platform permits that (secure enclave on phones, non-extractable
WebCrypto key in browsers).

Request shape under this mechanism:

| Header | Content |
|---|---|
| `X-Aivan-Device` | device id |
| `X-Aivan-Nonce` | server-issued, single-use nonce |
| `X-Aivan-Signature` | base64url, unpadded, signature over the canonical request string |
| `X-Aivan-Timestamp` | client clock, for skew rejection only |

Absent headers mean no proof, which is a denial and not an error.

Canonical string, defined exactly, with a fixed field order and a fixed
encoding:

```
aivan-v1 \n
METHOD \n
SCHEME://HOST \n
REQUEST-TARGET \n
SHA256(body) \n
nonce \n
timestamp
```

`REQUEST-TARGET` is the path plus the query string, taken verbatim. Covering
the query string is required (amendment A10): a signature over the path alone
lets one signature authorize `?id=1` and `?id=2`.

The query string is preserved byte for byte. The path is not: Traefik's
entrypoint decodes percent-encoded unreserved characters and uppercases hex
digits before routing, so `%41` arrives as `A`, `%7E` as `~`, `%2E` as `.` and
`%2f` as `%2F`, while the browser's `location.pathname` keeps the client's form.
Dot-segment and duplicate-slash normalisation also happens, but the browser
performs the same normalisation before sending. The service compares verbatim
and refuses a mismatch (amendment A22).

The values are taken from Traefik's `X-Forwarded-Method`, `-Proto`, `-Host` and
`-Uri`, which Traefik always sets and `authRequestHeaders` cannot suppress.
They are the only values the client and the gate can agree on, so a route that
rewrites its path before `forwardAuth` cannot be verified. The gate refuses a
request target it cannot reproduce rather than signing a different one.

Requirements:

- **Nonce is server-issued and single-use.** Consumed with an atomic
  compare-and-delete. A replay loses the race and is refused.
- **Nonce is short-lived.** Suggested 120 seconds. Expired nonces are refused
  and purged.
- **Timestamp skew is bounded.** Suggested 300 seconds, and the timestamp must
  not be older than the nonce issuance.
- **The signature must cover the method, host, request target, body hash, nonce,
  and timestamp.** Signing only the nonce would let one signature authorize any
  request until the nonce expired.
- **Verification is constant-time** on the signature comparison.
- **Algorithms are fixed and listed.** No algorithm identifier chosen by the
  client per request. Ed25519 is the preferred default; ES256 is accepted
  because it is the only scheme every mainstream browser has supported for a
  decade. The choice is made once, at enrollment, and recorded on the device
  row. Anything else is refused.

### 5.1.1 Nonce issuance

The nonce endpoint is necessarily unauthenticated: a client needs a nonce
before it can sign. Mitigations are part of the design, not hardening:

- It returns a nonce for any syntactically valid device id, whether or not that
  device exists, or it becomes a device-existence oracle (S14). Binding is
  enforced later, at verification, where the device row must match.
- It is rate limited per source address, with a table cap and a purge job, so
  it cannot be used to fill the table.

### 5.2 Mutual TLS (optional, later)

Not required for the first release. When enabled, it is per device:

- Traefik `passTLSClientCert` in the chain; the service reads the fingerprint
  from `X-Forwarded-Tls-Client-Cert`. Traefik deletes any incoming value of that
  header before setting the real one from the handshake, so the value stays
  trustworthy, but it must be in the same chain as the route.
- The service looks up `devices.fingerprint` and refuses an unknown or revoked
  device before any other check.
- Device certificates are self-signed and pinned by fingerprint. There is no
  client CA and no certificate hierarchy. The verifier is the database, so a
  CA would add a root key to protect without adding a boundary.
- `devices.proof` records which mechanism each device uses, so both coexist
  without a second table or a second code path.

A device certificate identifies a device, never a person. The subject is the
device id.

### 5.3 The password

This service has no password path at all. It never accepts a password, never
reads `password_digest`, and never writes one. The database credential it runs
under holds a column grant on `public.users (id, username, active)` and nothing
else, so a password is unreachable by privilege rather than by a code path this
service has to remember to disable.

What the predecessor's retirement rule protected against — bricking an install
by disabling the only working credential before a new one is proven — is
handled structurally here: enrollment requires a signature over the claim, so a
device row exists only for a key that has already proved possession.

Bootstrap therefore does not create a password either. It creates the person
and the admin membership (the application's own console task), and one pending
enrollment with a one-time code (this service's console task). See §6.5.

### 5.4 Session

After the first successful proof, the service mints a short-lived session so a
browser does not sign every request.

- Session lifetime: suggested 15 minutes idle, 8 hours absolute. The idle
  expiry slides, but is written back only when it has moved more than a minute,
  so a busy session does not cost a write per request.
- Sessions are **server-side**. Requirement S5 wants a revoke to be effective
  on the next request, and a stateless token cannot provide that.
- The session is bound to the device id, so a revoke invalidates outstanding
  sessions by deleting them in the same transaction that sets `revoked_at`.
- The cookie is `HttpOnly`, `SameSite=Lax` or stricter, `Secure`, `Path=/`, and
  carries the `__Host-` prefix, which forbids a `Domain` attribute and keeps it
  scoped to the one host. The token is stored hashed, so a database read does
  not yield a usable cookie.
- **Because the session is a cookie, CSRF is real.** Every state-changing
  request under a cookie session must carry either a CSRF token or a required
  custom header that a cross-origin form cannot set. This is a requirement, not
  a hardening recommendation. `Sec-Fetch-Site: same-site` is not sufficient: it
  includes sibling subdomains.
- A request that carries a device proof and no cookie needs no CSRF defense;
  the signature covers intent.
- Sessions are verified on every request. The service never caches an
  authorization decision across requests.
- **Session minting is a route, not a side effect.** A cookie set on a
  `forwardAuth` success is not delivered to the browser unless it is explicitly
  named in `addAuthCookiesToResponse`, and refreshing on every request would
  cost a write per request. The session is minted at a dedicated endpoint,
  reached through a router that does not pass through the forward-auth
  middleware. See §8.1.

## 6. Authorization

Authentication answers who. Authorization answers what, and this service is
where the "what" is decided.

### 6.1 Output contract

| Field | Header |
|---|---|
| user id | `X-Aivan-User-Id` |
| username | `X-Aivan-User` |
| device id | `X-Aivan-Device-Id` |
| device kind | `X-Aivan-Device-Kind` |
| roles | `X-Aivan-Roles` (comma separated, stable order) |
| auth mechanism | `X-Aivan-Proof` (`nonce`, `mtls`, or `session`) |
| request id | `X-Aivan-Request-Id`, generated by the gate |
| session | `X-Aivan-Session` **omitted** |

Rules:

- All values are opaque to the application. The application decides nothing
  from the username; it reads the user id.
- The session is not disclosed to the application (amendment A11). It is a
  bearer credential, and an application that logs its headers would leak it.
  The device id is the useful identity, and it is already sent.
- The service never returns a role the user no longer holds, because roles are
  resolved per request, not carried in the session.
- Header values are constrained to a safe character set; usernames that cannot
  be represented are refused rather than encoded.

### 6.2 Policy

Policy is per host and per route. A route declares who may reach it.

The host dimension is not optional: a device is bound to one origin (§4), so a
proof enrolled for one application must not be accepted by another.

Serving a public path from a router that does not pass through the gate is a
deployment requirement, not a policy class. A path that reaches the gate and is
classified public is a routing mistake, and is logged as one.

| Route class | Requirement |
|---|---|
| Public | no proof; no `X-Aivan-*` headers set |
| Enrollment claim | a valid pending enrollment; no user proof |
| Authenticated | any active device of an active user |
| Admin | a device proof plus membership in `admin` |
| Grant operations | a device proof plus an explicit grant; `act` scoped |

The "bootstrap only" class is withdrawn (amendment A12). There is no bootstrap
credential in this service, so there is no window in which a bootstrap-only
route would be meaningful.

Denial must be distinguishable to the operator while opaque to the client:

- `401` means no valid proof, and carries where to get one.
- `403` means a valid proof with insufficient authorization.
- Neither response reveals whether a named user or device exists.

### 6.3 Grants

The service issues and verifies signed grants. A grant is a small statement:

```
iss    device key
sub    user id
aud    the application or component
act    the operation
res    the object acted on
exp    expiry
nonce  server-issued, single use
```

- A grant is verified by the component it names, against an enrolled key. It is
  not a bearer token passed down a call chain.
- A grant carries the approval, not just the connection. This is what a TLS
  handshake cannot express and the reason grants are the core artifact.
- Grants are short-lived. Duration is per `act`, not global.
- A grant is single-use when the operation is not idempotent.

### 6.4 Devices and enrollment

A device row exists only after an approval. The record:

```
devices
  id             uuid, also the certificate subject when mTLS is used
  user_id        -> users
  origin         the one host this key belongs to
  name           operator-visible label
  kind           phone | tablet | browser
  alg            ed25519 | es256, chosen once at enrollment
  public_key     the enrolled key
  proof          nonce | mtls
  fingerprint    present when proof is mtls
  created_at
  last_seen_at
  revoked_at     present from the first migration
```

A device id is never a username, and never changes. An email or username change
must not invalidate a device.

A device belongs to exactly one origin, because a browser's key cannot leave
it (amendment A13). `origin` is enforced at verification, so a key enrolled on
one application is refused by another even with a valid signature. A user with
three applications has three browser devices. `kind` records the platform, so a
person holds at most one of each kind per application.

Enrollment requires an existing, single-use, identity-bearing pending record:

- The phone creates it, naming the user and, for an invite, the intended
  identity.
- The record carries a short code. The claiming device must present that code,
  and the code must appear inside the signed approval, together with the public
  key being enrolled.
- The record expires quickly and is consumed once.
- The claim binds the new device to the user named in the record. The claiming
  device never asserts its own identity.
- The claim is signed. Because the signature covers the code and the public
  key together, a captured claim cannot be repurposed with a different key, and
  a guessed code cannot be used without the matching key. A device row
  therefore exists only for a key that has proved possession.
- Without a matching pending record, the service refuses. There is no open
  enrollment path, by design.

### 6.5 Bootstrap

The first person and the first device are created out of band, on the compute
server, by the person holding cluster access.

Two console steps, split because this service cannot write `public.users`:

- The application's own console task creates the person and the `admin`
  membership.
- This service's console task creates one pending enrollment for that person
  and prints a short-lived code, once. It refuses when that person already has
  an active device of the requested kind, so a forgotten enrollment does not
  accumulate credentials.
- Neither step involves a password, and neither prints a private key. The key
  is generated on the device and never leaves it.

## 7. Data

### 7.1 Ownership

The service owns the tables that describe authentication state and reads the
tables that describe identity. Its tables live in their own schema, so
ownership is a namespace rather than a naming convention.

| Table | Access |
|---|---|
| `users` | read `id`, `username`, `active` only |
| `groups`, `groups_users` | read |
| `authz.devices` | read and write |
| `authz.nonces` | read and write |
| `authz.sessions` | read and write |
| `authz.pending_enrollments` | read and write |
| `authz.audit_log` | append |

The service has no access to `password_digest`. That is enforced by a
column-level grant rather than by a code path, and verified at boot (S16, S20).
It has no access to any application table that is not listed above.

Because the gate consumes a nonce before it verifies the signature — the
ordering that makes a replay lose the race — a `nonce` cannot carry a foreign
key to a device that may not exist. S14 is the reason.

### 7.2 Roles

Roles come from group membership in the application's database, resolved per
request.

- The role list is the group names the user belongs to.
- `admin` is the privileged role and is defined by group membership, never by a
  column.
- Ordering is stable so headers do not flap.
- A user with no groups authenticates and carries no roles.

### 7.3 Secrets and connections

- One database credential for this service. It is not the application's
  credential.
- Read-only where read-only is sufficient.
- Unprivileged container; no shell required at runtime.
- The service holds no cryptographic private key of its own. It verifies public
  keys. There is no CA to protect.

## 8. Operational contract

### 8.1 Traefik

The service is addressed as a `forwardAuth` target inside the cluster.

- `trustForwardHeader: false`.
- `authRequestHeaders` lists exactly what is needed: the device proof headers,
  the cookie, and the CSRF header. Nothing else.
- The `forwardAuth` `address` points at the gate's cluster service
  (`http://<gate-svc>.<ns>.svc:<port>/__aivan/verify`), never at an ingress
  host, so the call cannot recurse through the gate's own router.
- `authResponseHeadersRegex` is anchored (`^X-Aivan-`) so those headers are
  stripped from client requests before the service's values are set.
- `preserveRequestMethod: true`, because the method is covered by the
  signature.
- `forwardBody: true` with `maxBodySize` set, because the body hash is covered
  by the signature. The service enforces its own, lower limit and refuses with
  `413`; `maxBodySize` is the hard ceiling above it.
- `authSigninURL` is **unused**. It takes a static string with no placeholder
  for the original URL, so a return-to-origin redirect cannot be built from it.
  Instead the service returns its own `302` with a `rd` parameter, which
  Traefik passes through untouched.

Three further behaviours of the middleware are part of the contract because the
design depends on them:

- **`X-Forwarded-Method`, `-Proto`, `-Host` and `-Uri` are always set and
  cannot be suppressed** by `authRequestHeaders`. They are the only values the
  client and the service can agree on, so they are what the signature covers.
  Consequence: no path-rewriting middleware (`StripPrefix`, `ReplacePath`) may
  precede `forwardAuth` on a gated route.
- **A cookie set on an auth `200` is not delivered to the browser** unless it is
  named in `addAuthCookiesToResponse`. Session minting is therefore a separate
  route on a router that bypasses the middleware.
- **A non-2xx auth response reaches the client with its status and body
  unchanged**, which is what makes the `302` and the `401` in §6.2 reliable.
  The `Location` header does **not** arrive unchanged by default: Traefik
  resolves a relative `Location` against the auth service's own address and
  sends the browser an internal cluster URL. `preserveLocationHeader: true` on
  the middleware is required, and is part of the configuration below.
- **`authResponseHeadersRegex` applies to the response to the application
  only.** It does not strip matching headers from the request Traefik sends to
  this service, so a client-supplied `X-Aivan-User` reaches the auth hop if it
  is listed in `authRequestHeaders`. Identity headers must therefore never be
  listed there, and the service treats any `X-Aivan-*` request header other than
  the four proof headers as untrusted input. On a non-2xx response the auth
  response *is* the client's response, so matching headers reach the browser;
  the service sets no identity header on a denial or a redirect.

Required `forwardAuth` fields, as observed on Traefik 3.7.13:

```yaml
forwardAuth:
  address: "http://<gate-svc>.<ns>.svc:8080/__aivan/verify"
  trustForwardHeader: false
  authResponseHeadersRegex: "^X-Aivan-"
  authRequestHeaders: [X-Aivan-Device, X-Aivan-Nonce, X-Aivan-Signature,
                       X-Aivan-Timestamp, Cookie]
  addAuthCookiesToResponse: [<session cookie name>]
  preserveRequestMethod: true
  forwardBody: true
  maxBodySize: <ceiling>
  preserveLocationHeader: true
```

`preserveRequestMethod` and `forwardBody` are both load-bearing: without them
the auth hop receives a `GET` with an empty body while `X-Forwarded-Method`
still names the real method, so `SHA256(body)` cannot be computed.

The service must be reachable only from Traefik. A direct path to it is a
bypass.

### 8.2 Latency and failure

- Target: a single-digit millisecond decision for a nonce-verified request on
  the local network, excluding the client's own TLS work.
- Budget: one database round trip per request for the common path. No query per
  role.
- Timeout: the service must answer within a configured budget shorter than the
  slowest acceptable user wait. Traefik's `forwardAuth` timeout is a hardcoded
  30 s with no configuration field (`ServersTransport` does not apply to the
  auth call), so that bound cannot come from Traefik and must be enforced inside
  the service: an `http.Server` write timeout and a per-request context
  deadline. Observed: an auth service that hangs makes the user wait 30.0 s and
  then receive Traefik's `500`.
- **Failure is closed.** If the service is unreachable or errors, protected
  routes are refused. If a route was allowed while the service was healthy, it
  is refused while the service is unhealthy. This matches the predecessor's
  `failure_mode_allow: false`.
- The public surface (the galaxy page and its assets) is not behind this
  service, so an auth outage does not blank the whole application.

### 8.3 Observability

- Every decision is logged with: timestamp, user id or "anonymous", device id,
  route, decision, and reason code.
- No secrets, no signatures, no cookie values, no full public keys in logs.
- Denials are counted by reason, because a spike in one reason is the signal
  that matters.
- A request id is generated at the gate, logged with the decision, and returned
  as `X-Aivan-Request-Id` so an application error can be tied to that decision.
  It is generated, never taken from the client.

### 8.4 Health

- A readiness check that proves the database is reachable, because a gate that
  cannot read `devices` must not be in rotation.
- A liveness check that does not depend on the database, so a database outage
  does not trigger an endless restart loop.

## 9. Security requirements

These are requirements, not suggestions. Each has a test.

Two notes on how to read this table. S15 covers the comparison the service
performs itself; Ed25519 and ES256 verification inside a library is expected to
be constant-time and is not re-implemented here. S16 and S20 are checks the
service performs against its own credential at boot, so a misconfigured deploy
fails loudly instead of quietly holding more privilege than the design assumes.
S21 has no test in the gate alone: it needs two gated hosts, so it is proved
against the cluster.

| # | Requirement |
|---|---|
| S1 | A replayed nonce is refused. |
| S2 | A signature is refused if any covered field changes. |
| S3 | An expired nonce is refused. |
| S4 | A clock-skewed request is refused. |
| S5 | A revoked device is refused, and its outstanding sessions are too. |
| S6 | A client-supplied `X-Aivan-*` header cannot reach the application. |
| S7 | A user with no roles cannot act as a user with roles. |
| S8 | A device bound to user A cannot act as user B. |
| S9 | An enrollment claim without a valid pending record is refused. |
| S10 | An enrollment claim with a mismatched code is refused. |
| S11 | An enrollment claim cannot bind a device to a user that the pending record does not name. |
| S12 | Withdrawn in revision 2: this service has no password path. Replaced by S20. |
| S13 | A state-changing request under a cookie session without a CSRF token or required custom header is refused. |
| S14 | Neither a denial nor an error reveals whether a user or device exists. |
| S15 | Signature comparison and nonce comparison are constant-time. |
| S16 | The service refuses to start when its database credential can write outside its own tables. |
| S17 | An algorithm not on the fixed list is refused. |
| S18 | A body larger than the configured maximum is refused, not truncated. |
| S19 | A signature that covers the path does not authorize a different query string. |
| S20 | The service's credential cannot read `password_digest`. |
| S21 | A device enrolled on one origin is refused on another. |

## 10. Non-goals

Explicit, so they are not quietly assumed:

- Issuing or managing a certificate authority.
- Storing private keys, for any client.
- Being a session store for the applications behind it.
- Rendering any user interface beyond the enrollment page. That page is one
  static document that runs WebCrypto in the browser and renders no
  application data. It exists because the credential is generated on the
  device, so the device needs somewhere to generate it (amendment A14).
- Managing users: creating, deleting, or renaming them.
- Recovery of a lost device. A revoke is available; the recovery procedure is a
  later document.
- Pushing approvals to the phone. The phone polls or is invoked separately.
- Authorization decisions that need application-specific business rules. The
  gate decides role and grant; the application decides what a role means for
  its own data.

## 11. Acceptance

The first release is acceptable when all of these hold:

1. Traefik sends every protected request through this service.
2. A browser with an enrolled device key reaches a protected route with a
   short-lived session.
3. A request with no proof is refused with a redirect target, and the
   application never sees it.
4. A request with a forged `X-Aivan-User` header is refused, and the header does
   not reach the application.
5. A replayed signed request is refused.
6. A revoked device is refused within one request of the revoke.
7. The service's credential cannot read `password_digest` or write outside its
   own schema, and the service refuses to start if it can.
8. Each requirement in section 9 has a test that fails when the requirement is
   removed.
9. The decision path holds its latency budget under the load profile in
   section 8.2.
10. The service is unreachable from anywhere except Traefik.

## 12. Decisions

Settled while planning. The reasoning is in `doc/aivan-initial-plan.md`.

1. **Language: Go 1.26.** A single static binary with no interpreter to patch
   is worth more than the reuse of `van-auth` for a component whose absence is
   a security event. The measured cost in `van-auth` was already acceptable, so
   latency did not decide this. Reversibility is preserved by keeping the
   schema in plain SQL and the hot path a single hand-written statement.
2. **Sessions: server-side.** Requirement S5 wants revoke effective on the next
   request, which a stateless token cannot provide. The lookup is free because
   it is the same round trip as the device read.
3. **Where the body hash is required: everywhere the body can exist**, with a
   configured maximum and `413` above it. Traefik forwards the body with
   `maxBodySize` as a hard ceiling; the service enforces the real limit.
4. **Nonce lifetime and session lifetime:** 120 seconds and 15 minutes idle /
   8 hours absolute as first values, to be revised against real usage after
   sessions ship.
5. **One service, per-host policy.** A second identity system is the failure
   this project exists to prevent.
6. **Whether a phone can act on behalf of a browser during enrollment without
   the browser's code: no.** The browser's key is generated in the browser and
   the code is bound into the signed claim, so the phone cannot substitute.
7. **Algorithms: Ed25519 preferred, ES256 accepted** (amendment A15). ES256 is
   included because it is the only scheme with a decade of universal WebCrypto
   support; Ed25519 only reached Chrome in mid-2025. The choice is fixed per
   device at enrollment, never chosen per request.
8. **Per-origin devices** (amendment A13). WebCrypto keys cannot cross origins,
   so this is a constraint rather than a preference.

## 13. Glossary

- **Device proof** — evidence that a request comes from a specific enrolled
  device. Either a signed nonce or a client certificate.
- **Nonce** — a server-issued value, single use, short-lived, consumed
  atomically.
- **Grant** — a signed statement naming an actor, an audience, an action, a
  resource, and an expiry.
- **Pending enrollment** — a single-use, identity-bearing record created before
  a device claims it.
- **Bootstrap** — the out-of-band creation of the first person and the first
  pending enrollment on the compute server. It involves no password.
- **Request target** — the path plus query string, as the client produced it and
  as `X-Forwarded-Uri` reports it. Covered by the signature.
- **Forward auth** — the proxy pattern where the gate is called before the
  upstream, and only its approval reaches the upstream.

## 14. Amendments

Each is a place where revision 1 was wrong or under-specified.

| # | Amendment |
|---|---|
| A10 | The canonical string covers the request target (path plus query), not the path alone. |
| A11 | `X-Aivan-Session` is omitted; the session token is never disclosed to the application. |
| A12 | The "bootstrap only" route class is withdrawn, along with S12 and the password retirement in §5.3, which becomes "the password does not exist here". |
| A13 | Devices are scoped per origin, because a WebCrypto key cannot cross one. |
| A14 | The no-UI non-goal permits exactly one static enrollment page. |
| A15 | ES256 joins Ed25519 on the fixed algorithm list, chosen once per device. |
| A16 | `authSigninURL` is unused; the gate owns the `302`, because the option cannot carry the original URL. |
| A17 | Session minting is a dedicated route; a cookie on a forward-auth `200` does not reach the browser. |
| A18 | `413` is the gate's answer for an oversized body; `maxBodySize` is a ceiling and returns `401`. |
| A19 | Policy gains a host dimension, since a device is bound to one origin. |
| A20 | The service fails to start if its credential can read `password_digest` (S20). |
| A21 | A device is refused on a host other than the one it was enrolled on (S21), enforced from `devices.origin`. |
| A22 | The request target is compared verbatim and refused on mismatch, because Traefik normalises percent-encoding in the path before routing while the browser does not. Test vectors use only characters that survive that normalisation. |
| A23 | `preserveLocationHeader: true` is required on the `forwardAuth` middleware; the default rewrites a relative `Location` to the auth service's cluster address. |
