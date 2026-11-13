# Traefik forwardAuth contract, as observed

Cluster: k3s v1.36.5+k3s1, single node. Traefik 3.7.13 (langres, go1.26.8), served
by the `websecure` entrypoint (`:8443`, exposed as `:443` on 192.168.192.2).
Probe: `echo.aivan.svc.cluster.local:8080` in namespace `aivan`, reached through
hosts `aivan-echo.home.arpa` (the gated route) and `echo-*.home.arpa` variants.
Date: 2026-11-13. All output below is verbatim, captured with `curl -sk`.

Notes on how this was run, because they change how to read it:

- `aivan-echo.home.arpa` has no DNS record in the house resolver, so every
  request used `--resolve aivan-echo.home.arpa:443:192.168.192.2`. Routing is
  identical to a resolver-backed name; only name resolution differs.
- The probe's TLS certificate is self-signed for
  `aivan-echo.home.arpa` (`aivan-echo-tls`). `Secure` cookies and redirects are
  observable over HTTPS with `curl -k`. Browser-side checks used headless
  Firefox to get the exact `URL` parser behaviour.
- Traefik calls the middleware `address` **verbatim**. The client's querystring
  is **not** appended: for a client request to `/a%20b?x=1&y=%2F`, the auth hop
  received `X-Forwarded-Uri: /a%20b?x=1&y=%2F` but its own query string was
  empty, and a client request to `/one?mode=deny` was still allowed. Driving the
  auth service's response mode from the client's URL is therefore impossible,
  which is a security property worth keeping in mind: one middleware per
  response mode was used instead.
- Two runs are recorded. The first used probe hosts `aivan-echo.home.arpa` and
  `echo-*.home.arpa` with a service named `echo`. The second (`echo3*`
  hostnames) re-ran the same checks against `ruby:4.0.5-slim-trixie` with the
  final echo script from the phase file, to confirm the findings reproduce on an
  independent probe and to check cases the first echo could not express, such as
  where auth-response headers go on a `200`. Every finding agrees between the
  two; the second run is quoted where it added detail.

## Header strip

Middleware `aivan-auth-probe` with `authResponseHeadersRegex: "^X-Aivan-"` and an
explicit `authRequestHeaders` list. The client sends forged identity headers.

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    https://aivan-echo.home.arpa/one \
    -H 'X-Aivan-User: attacker' -H 'X-Aivan-User-Id: 1' \
    -H 'X-Aivan-Roles: root' -H 'X-Aivan-Extra: injected' \
  | jq '.headers | with_entries(select(.key|test("^x-aivan-(user|roles|extra)")))'
{
  "x-aivan-roles": "admin,free",
  "x-aivan-user": "from-auth",
  "x-aivan-user-id": "42"
}
```

`X-Aivan-Extra` is absent because the auth response did not set it: **every**
request header matching `^X-Aivan-` is removed and only headers present in the
auth response are restored. The forged `X-Aivan-User`, `-User-Id` and `-Roles`
never reached the backend.

Control, with the middleware removed (`echo-probe-nomw`, no middleware on the
router):

```console
$ curl -sk --resolve echo-nomw.home.arpa:443:192.168.192.2 \
    https://echo-nomw.home.arpa/one \
    -H 'X-Aivan-User: attacker' -H 'X-Aivan-User-Id: 1' -H 'X-Aivan-Roles: root' \
  | jq '.headers | with_entries(select(.key|test("^x-aivan")))'
{
  "x-aivan-roles": "root",
  "x-aivan-user": "attacker",
  "x-aivan-user-id": "1"
}
```

The strip is real: the same request passes untouched when the middleware is
absent.

One consequence that the gate must not get wrong: the regex is applied to the
*response* path to the backend. It does **not** remove matching headers from the
request Traefik sends to the auth service. With `X-Aivan-User` added to
`authRequestHeaders`, a client-supplied `X-Aivan-User: attacker` arrives at the
auth hop:

```console
$ curl -sk --resolve echo-striptest.home.arpa:443:192.168.192.2 \
    https://echo-striptest.home.arpa/one -H 'X-Aivan-User: attacker' -H 'X-Aivan-Device: d1' \
  | jq -r '.headers["x-aivan-auth-headers"]'
accept-encoding,host,user-agent,x-aivan-device,x-aivan-user,x-forwarded-for,x-forwarded-host,x-forwarded-method,x-forwarded-port,x-forwarded-proto,x-forwarded-uri
```

So the gate's identity headers (`X-Aivan-User`, `-User-Id`, `-Roles`, ...) must
never appear in `authRequestHeaders`, and the gate must treat any that do arrive
as untrusted input. The proof headers (`X-Aivan-Device`, `-Nonce`, `-Signature`,
`-Timestamp`) are the only `X-Aivan-*` values it may read.

## Non-2xx passthrough

### 401

```console
$ curl -sk --resolve echo-deny.home.arpa:443:192.168.192.2 \
    -D- https://echo-deny.home.arpa/one
HTTP/2 401
www-authenticate: Aivan
content-length: 20
date: Fri, 13 Nov 2026 18:22:02 GMT

{"error":"no proof"}
```

Status, body and `WWW-Authenticate` arrive intact. Where the auth response's
`X-Aivan-*` headers go depends on the status:

- On a **2xx**, they are copied onto the request forwarded to the backend and
  are **not** visible to the client.
- On a **non-2xx**, the auth response becomes the client's response, so its
  headers reach the client. Verified on `401` and `302`: eight `X-Aivan-Auth-*`
  headers, plus `Set-Cookie` when `addAuthCookiesToResponse` is set.

```console
$ curl -sk --resolve echo3-deny.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://echo3-deny.home.arpa/h | grep -ci 'x-aivan-auth'
8
$ curl -sk --resolve echo3.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- 'https://echo3.home.arpa/h?a=1' | grep -i 'x-aivan'
(no output — on a 200 they go to the backend instead)
```

Consequence for the gate: it must not set identity headers on a denial or a
redirect, because the browser would receive them. The reason code and request id
on a denial are safe to expose deliberately, and `X-Aivan-Request-Id` is
intended to be visible.

### 302 — Location is rewritten unless told not to

This is the finding that contradicts the plan. Default middleware, no
`preserveLocationHeader`:

```console
$ curl -sk --resolve echo-redirect.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://echo-redirect.home.arpa/one
HTTP/2 302
location: http://echo.aivan.svc.cluster.local:8080/__aivan/enroll?rd=%2Fadmin
content-length: 0
date: Fri, 13 Nov 2026 18:13:39 GMT
```

Traefik resolved the relative `Location: /__aivan/enroll?rd=%2Fadmin` against the
**auth service's own address** and handed the browser an internal cluster URL.
`curl` did not follow it (`-o /dev/null -D-`); a browser would follow it and fail
to reach `echo.aivan.svc.cluster.local`.

With `preserveLocationHeader: true`:

```console
$ curl -sk --resolve echo-redirect2.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://echo-redirect2.home.arpa/one
HTTP/2 302
location: /__aivan/enroll?rd=%2Fadmin
content-length: 0
date: Fri, 13 Nov 2026 18:13:49 GMT
```

Byte-identical to what the auth service returned. The status is not rewritten
either way; only `Location` is. `preserveLocationHeader: true` is mandatory on
the gate's middleware.

### 500 from the auth service

```console
$ curl -sk --resolve echo-fail.home.arpa:443:192.168.192.2 \
    -D- https://echo-fail.home.arpa/one
HTTP/2 500
content-length: 13
date: Fri, 13 Nov 2026 18:13:39 GMT

auth exploded
```

A 5xx from the auth service reaches the client with its body. The gate's own
error responses are therefore visible, which matters for not leaking internals:
the gate must write its own body deliberately.

## Cookie forwarding

Auth service sets
`Set-Cookie: aivan_session=probe; Path=/; Secure; HttpOnly; SameSite=Lax` on a
200, with `addAuthCookiesToResponse: ["aivan_session"]` on the middleware:

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://aivan-echo.home.arpa/one
HTTP/2 200
content-type: application/json
set-cookie: aivan_session=probe; Path=/; HttpOnly; Secure; SameSite=Lax
content-length: 1105
date: Fri, 13 Nov 2026 18:13:55 GMT
```

Identical middleware with `addAuthCookiesToResponse` removed:

```console
$ curl -sk --resolve echo-nocookie.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://echo-nocookie.home.arpa/one
HTTP/2 200
content-type: application/json
content-length: 1121
date: Fri, 13 Nov 2026 18:14:04 GMT
```

No `Set-Cookie`. The plan's claim holds: without the option the cookie is
dropped; with it, it is delivered. Traefik also reordered the attributes
(`Secure` before `SameSite`) and preserved their values.

A 302 that carries a `Set-Cookie`, with both `addAuthCookiesToResponse` and
`preserveLocationHeader` set, delivers both, and because it is a non-2xx the
auth response's other headers go to the client too:

```console
$ curl -sk --resolve echo-rc.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- https://echo-rc.home.arpa/one
HTTP/2 302
location: /__aivan/enroll?rd=%2Fadmin
set-cookie: aivan_session=probe; Path=/; HttpOnly; Secure; SameSite=Lax
x-aivan-auth-method: GET
x-aivan-auth-uri: /one
content-length: 0
date: Fri, 13 Nov 2026 18:20:38 GMT
```

(The `x-aivan-auth-*` lines come from the probe's own dump; a real gate would
set no `X-Aivan-*` header on a redirect or a denial.)

This is what makes mint-on-redirect possible, though the design keeps session
minting on its own router (`/__aivan/session`) and does not need it.

## Forwarded values

### The four headers the signature covers

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    'https://aivan-echo.home.arpa/a%20b?x=1&y=%2F' \
  | jq '{uri: .headers["x-aivan-auth-uri"], method: .headers["x-aivan-auth-method"],
         proto: .headers["x-aivan-auth-proto"], host: .headers["x-aivan-auth-host"]}'
{
  "uri": "/a%20b?x=1&y=%2F",
  "method": "GET",
  "proto": "https",
  "host": "aivan-echo.home.arpa"
}
```

These are the values as the *auth hop* saw them (`/auth` echoes what it
received under `X-Aivan-Auth-*`). The plan's sample target round-trips byte for
byte.

`POST` with a body:

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    -X POST --data-binary 'hello' 'https://aivan-echo.home.arpa/a%20b?x=1&y=%2F' \
  | jq '{uri: .headers["x-aivan-auth-uri"], method: .headers["x-aivan-auth-method"],
         backend_method: .method, auth_body_len: .headers["x-aivan-auth-bodylen"],
         backend_body_sha256: .body_sha256}'
{
  "uri": "/a%20b?x=1&y=%2F",
  "method": "POST",
  "backend_method": "POST",
  "auth_body_len": "5",
  "backend_body_sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}
```

`X-Forwarded-Method` is `POST`, and `forwardBody: true` delivered the exact body
(`sha256("hello")` matches).

Every method reaches the auth hop under its own name with
`preserveRequestMethod: true`. The auth service logged the method it received,
per client method:

```console
AUTHHOP method=GET uri=/x?v=1 xfm=GET
AUTHHOP method=HEAD uri=/x?v=1 xfm=HEAD
AUTHHOP method=DELETE uri=/x?v=1 xfm=DELETE
AUTHHOP method=OPTIONS uri=/x?v=1 xfm=OPTIONS
AUTHHOP method=PATCH uri=/x?v=1 xfm=PATCH
```

Without it, every method arrives as `GET` while `X-Forwarded-Method` still names
the real one:

```console
AUTHHOP method=GET uri=/x xfm=GET
AUTHHOP method=GET uri=/x xfm=POST
AUTHHOP method=GET uri=/x xfm=HEAD
AUTHHOP method=GET uri=/x xfm=DELETE
AUTHHOP method=GET uri=/x xfm=OPTIONS
AUTHHOP method=GET uri=/x xfm=PATCH
AUTHHOP method=GET uri=/x xfm=PUT
```

`HEAD` in particular is preserved, not downgraded.

### Which headers reach the auth hop

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    https://aivan-echo.home.arpa/one | jq -r '.headers["x-aivan-auth-headers"]'
accept-encoding,host,user-agent,x-forwarded-for,x-forwarded-host,x-forwarded-method,x-forwarded-port,x-forwarded-proto,x-forwarded-uri
```

`X-Forwarded-*` are present regardless of `authRequestHeaders`. `Cookie` is
present only when listed (confirmed by removing it: the list lost `cookie`,
while `x-forwarded-*` stayed). `X-Forwarded-Port` and `X-Real-Ip` also appear,
both injected by Traefik and not suppressible.

### `X-Forwarded-Uri` is normalised before routing

This is the second finding that contradicts the plan. The querystring is
preserved exactly; the **path** is not.

| Client request target | `X-Forwarded-Uri` at the auth hop |
|---|---|
| `/A` | `/A` |
| `/a//b` | `/a/b` |
| `/a/./b` | `/a/b` |
| `/a/../b` | `/b` |
| `/%2F` | `/%2F` |
| `/%2f` | `/%2F` |
| `/a%2Bb` | `/a%2Bb` |
| `/a+b` | `/a+b` |
| `/a%3Fb` | `/a%3Fb` |
| `/a?b=%26` | `/a?b=%26` |
| `/a?` | `/a` |
| `/café` | `/caf%C3%A9` |
| `/a%2Eb` | `/a.b` |
| `/%7Euser` | `/~user` |
| `/%41` | `/A` |
| `/a%00b` | `/a%00b` |

Traefik's entrypoint does three things before routing (documented in
`https://doc.traefik.io/traefik/security/request-path/`, and reproduced above):
encoded-character filtering, then always-on path normalisation that decodes
percent-encoded **unreserved** characters (RFC 3986 §2.3) and uppercases hex
digits (RFC 3986 §6.2.2.1), then optional `sanitizePath` (default true) which
removes dot-segments and collapses duplicate slashes.

The same normalisation applies with no middleware at all, so it is the
entrypoint's behaviour, not `forwardAuth`'s.

What the browser does with the same inputs (headless Firefox, `new URL()`):

| Input | `location.pathname` | `location.search` |
|---|---|---|
| `/a/./b` | `/a/b` | `` |
| `/a/../b` | `/b` | `` |
| `//x` | `//x` | `` |
| `/a//b` | `/a//b` | `` |
| `/%41` | `/%41` | `` |
| `/%7Euser` | `/%7Euser` | `` |
| `/a%2Eb` | `/a%2Eb` | `` |
| `/%2f` | `/%2f` | `` |
| `/a%20b?x=1&y=%2F` | `/a%20b` | `?x=1&y=%2F` |

The two sides agree on dot-segments (the browser normalises those in the URL
parser before it sends anything, so `/a/../b` never reaches the wire as such) and
agree exactly on the querystring. They **disagree** in three places:

- Percent-encoded unreserved characters: `%41`, `%7E`, `%2E` are decoded by
  Traefik and kept by the browser.
- The hex case of reserved ones: `%2f` becomes `%2F` at Traefik.
- Duplicate slashes: Traefik collapses `/a//b` to `/a/b`; the browser preserves
  it in `pathname`, so the two strings differ.

A related check that came out benign: `%00` is left as the four characters
`%00` and does **not** become a raw NUL byte (`/a%00b` arrived as `/a%00b`). The
gate can treat the target as text, but it still should not decode it before
hashing and comparing.

Consequence for Phase B's test vectors: a target containing `%41`, `%7E`,
`%2E`, lower-case hex, or a duplicate slash will be signed by the browser in one
form and delivered by Traefik in another, so it will fail verification. That is
the correct outcome (refuse, do not guess) and it is cheap to avoid: build
vectors from characters that survive normalisation — `a-z`, `A-Z`, `0-9`, `-._~`
written literally, space as `%20`, `/` in the query as `%2F` with capitals, and
query punctuation, and no repeated slashes. Do **not** normalise the client's
string to match: two distinct client strings would then produce one target,
which is the collision the signature exists to prevent.

### Client cannot poison them

```console
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    https://aivan-echo.home.arpa/real \
    -H 'X-Forwarded-Uri: /fake' -H 'X-Forwarded-Host: evil.example' \
    -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Method: DELETE' \
    -H 'X-Forwarded-For: 9.9.9.9' -H 'X-Real-Ip: 9.9.9.9' \
  | jq '{uri: .headers["x-aivan-auth-uri"], host: .headers["x-aivan-auth-host"],
         proto: .headers["x-aivan-auth-proto"], method: .headers["x-aivan-auth-method"],
         xff: .headers["x-forwarded-for"], real_ip: .headers["x-real-ip"]}'
{
  "uri": "/real",
  "host": "aivan-echo.home.arpa",
  "proto": "https",
  "method": "GET",
  "xff": "192.168.196.66",
  "real_ip": "192.168.196.66"
}
```

With `trustForwardHeader: false` every forged value was replaced. The backend
also saw only Traefik's values. This is the property the trust model needs.

### Path rewriting before `forwardAuth`

A `StripPrefix` placed **before** `forwardAuth` changes the value the auth hop
sees, so the client's signature can no longer match:

```console
$ # middlewares: [strip-prefix /api, forwardAuth]  — the forbidden order
$ curl -sk --resolve echo-strip.home.arpa:443:192.168.192.2 \
    'https://echo-strip.home.arpa/api/x?q=1' \
  | jq '{target, auth_uri: .headers["x-aivan-auth-uri"]}'
{
  "target": "/x?q=1",
  "auth_uri": "/x?q=1"
}

$ # middlewares: [forwardAuth, strip-prefix /api]  — forwardAuth sees the original
$ curl -sk --resolve echo-strip2.home.arpa:443:192.168.192.2 \
    'https://echo-strip2.home.arpa/api/x?q=1' \
  | jq '{target, auth_uri: .headers["x-aivan-auth-uri"]}'
{
  "target": "/x?q=1",
  "auth_uri": "/api/x?q=1"
}
```

The plan's rule is correct and now has an observation behind it: any middleware
that rewrites the path must sit **after** `forwardAuth`, or the route cannot be
verified at all.

### `preserveRequestMethod` and `forwardBody` are both load-bearing

With neither set, a `POST` is delivered to the auth service as a `GET` with no
body, while `X-Forwarded-Method` still says `POST`:

```console
$ curl -sk --resolve echo-nopreserve.home.arpa:443:192.168.192.2 \
    -X POST --data-binary 'hello' https://echo-nopreserve.home.arpa/p \
  | jq '{backend_method:.method, auth_method:.headers["x-aivan-auth-method"],
         auth_reqmethod:.headers["x-aivan-auth-reqmethod"],
         auth_bodylen:.headers["x-aivan-auth-bodylen"]}'
{
  "backend_method": "POST",
  "auth_method": "POST",
  "auth_reqmethod": "GET",
  "auth_bodylen": "0"
}
```

`preserveRequestMethod: true` alone fixes the method but not the body:

```console
$ curl -sk --resolve echo-nobody.home.arpa:443:192.168.192.2 \
    -X POST --data-binary 'hello' https://echo-nobody.home.arpa/p \
  | jq '{auth_method:.headers["x-aivan-auth-method"],
         auth_reqmethod:.headers["x-aivan-auth-reqmethod"],
         auth_bodylen:.headers["x-aivan-auth-bodylen"]}'
{
  "auth_method": "POST",
  "auth_reqmethod": "POST",
  "auth_bodylen": "0"
}
```

A gate that cannot read the body cannot compute `SHA256(body)` and so cannot
verify a request that has one. Both options are required exactly as the spec
says.

## Auth service down

Deployment scaled to zero, so the service has no endpoints:

```console
$ kubectl -n aivan scale deploy echo --replicas=0
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    -D- --max-time 40 https://aivan-echo.home.arpa/one
HTTP/2 500
content-length: 0
date: Fri, 13 Nov 2026 18:23:44 GMT

TIME=0.014180 CODE=500
```

Failure is closed: `500` with an empty body, in 14 ms (connection refused, no
retry). Spec §8.2's requirement is satisfied.

A **hanging** auth service is the case that sets the user's worst-case wait. The
auth service slept 5 s, then 30 s, then 31 s, then 60 s:

| Auth response delay | Client result | Client wait |
|---|---|---|
| 5 s | `200` (allowed) | 5.02 s |
| down (refused) | `500` | 0.014 s |
| 30 s | `500` | 30.01 s |
| 31 s | `500` | 30.01 s |
| 60 s | `500` | 30.01 s |

`forwardAuth` has a **hardcoded 30 s timeout** and no configuration field for
it; `ServersTransport` does not apply to the auth call. So the gate's own
timeout must be well under 30 s or the user waits for Traefik's, which is longer
than any acceptable page load. Spec §8.2's "Traefik's timeout must be shorter
than the slowest acceptable user wait" cannot be satisfied by Traefik
configuration alone: the bound has to be enforced in the gate (its own
`http.Server` write timeout and its per-request deadline), and the failure shows
up as Traefik's `500` either way.

## Body size

`maxBodySize: 1048576` on the middleware.

```console
$ head -c 2000000 /dev/zero | tr '\0' 'a' > /tmp/big.txt
$ curl -sk --resolve aivan-echo.home.arpa:443:192.168.192.2 \
    -o /dev/null -D- -X POST --data-binary @/tmp/big.txt \
    https://aivan-echo.home.arpa/one
HTTP/2 401
content-length: 0
date: Fri, 13 Nov 2026 18:15:31 GMT

CODE=401 TIME=0.009882
```

Confirmed `401` as the docs say, with an empty body and no `WWW-Authenticate`.
The boundary is exact:

| Body bytes | Result |
|---|---|
| 1048576 (= `maxBodySize`) | `200`, allowed |
| 1048577 | `401` |
| 2000000 | `401` |

The two are distinguishable by status: this `401` means "the body was never shown
to the gate", while the gate's `413` means "the gate looked and refused". A
client that sees `401` on a large upload learns only that the upload did not
happen. Keeping the gate's own limit below the ceiling means the `413` is what
users normally get, and the `401` only appears for a body that is refused before
it is read.

## Conclusions

- **`X-Forwarded-Uri` reproducible?** Yes for the querystring and for paths made
  of unreserved characters written literally, with no repeated slashes. No for
  percent-encoded unreserved characters, lower-case hex in reserved ones, and
  duplicate slashes: Traefik decodes `%41`→`A`, `%7E`→`~`, `%2E`→`.` and
  uppercases `%2f`→`%2F` at the entrypoint while the browser's
  `location.pathname` preserves the client's form, and Traefik collapses
  `/a//b`→`/a/b`. Dot-segments normalise on both sides, so they do not diverge
  in practice. The gate must compare the client's string to `X-Forwarded-Uri`
  verbatim and refuse on mismatch; it must not normalise to make them agree.
- **302 reachable with `Location` intact?** Yes, and only with
  `preserveLocationHeader: true`. Without it Traefik rewrites `Location` to an
  absolute URL on the auth service's cluster address, which a browser cannot
  reach. The status is passed through either way.
- **Cookie needs `addAuthCookiesToResponse`?** Yes. Without it `Set-Cookie` from
  the auth response is dropped. With it, cookies are forwarded on both `200` and
  `302`.
- **Status when auth is unreachable?** `500` with an empty body, immediately.
  When the auth service hangs, `500` after exactly 30 s, a hardcoded Traefik
  timeout.
- **Anything that contradicts `doc/aivan-initial-plan.md` §2 or §5.1?**

  1. Plan §5.1 and spec §5.1 say the request target is taken *verbatim* from
     `X-Forwarded-Uri`, and the Phase A checklist demands the percent-encoding
     be unnormalised. The querystring is verbatim; the path is normalised by the
     entrypoint. Corrected in the plan and spec.
  2. Plan §5.2 and spec §8.1 say a non-2xx auth response reaches the client
     unchanged, "`Location` and body included". The body, status and
     `WWW-Authenticate` do; `Location` is rewritten to an absolute URL on the
     auth service's address unless `preserveLocationHeader: true` is set. The
     spec's middleware list did not include it. Corrected in the plan and spec.

  Two further observations worth acting on, neither a contradiction:

  3. Spec §8.2 expects Traefik's timeout to be shorter than the acceptable user
     wait. `forwardAuth`'s timeout is a hardcoded 30 s with no configuration
     field, so the bound must be enforced in the gate. Recorded in spec §8.2.
  4. `authResponseHeadersRegex` decides what is copied to the backend on a 2xx,
     and on a non-2xx the auth response becomes the client's response. In
     neither case does the regex strip matching headers from the request sent to
     the auth service. The gate must never read identity from `X-Aivan-*` input
     headers, must not put them in `authRequestHeaders`, and must set no
     identity header on a denial or a redirect. Recorded in spec §8.1.

## Probe inventory

Everything was applied in namespace `aivan` and removed at the end of Phase A;
after teardown the namespace holds only its `kube-root-ca.crt` ConfigMap, and
`https://aivan-echo.home.arpa/one` answers a bare Traefik `404`. To re-run, the
middleware and router files are reproduced in `doc/implementation-phase-a.md`.

- ConfigMap `echo-src`, Deployment `echo`, Service `echo`.
- Secret `aivan-echo-tls` (self-signed for `aivan-echo.home.arpa`).
- Middlewares: `aivan-auth-probe` (the plan's configuration),
  `aivan-auth-deny`, `aivan-auth-redirect`, `aivan-auth-redirect-preserve`,
  `aivan-auth-nocookie`, `aivan-auth-nocookiehdr`, `aivan-auth-fail`,
  `aivan-auth-slow`, `aivan-auth-slow2`, `aivan-auth-slow31`,
  `aivan-auth-slow60`, `aivan-auth-rc`, `aivan-auth-nopreserve`,
  `aivan-auth-nobody`, `aivan-auth-striptest`, `aivan-auth-final`,
  `echo-method-query`, `strip-probe`.
- IngressRoutes: `echo-probe`, `echo-probe-modes`, `echo-probe-preserve`,
  `echo-probe-nocookie`, `echo-probe-nocookiehdr`, `echo-probe-nomw`,
  `echo-probe-slow2`, `echo-probe-slow60`, `echo-probe-slow31`, `echo-probe-rc`,
  `echo-probe-defaults`, `echo-probe-striptest`, `echo-probe-strip`,
  `echo-probe-final`.

One deviation from the phase file worth recording: the plan drove the auth
service's response mode with `?mode=` on the client's own URL. That cannot work,
because Traefik calls the middleware `address` verbatim and does not append the
client's query string (observed: `x-aivan-auth-query` is empty). Each mode needs
its own middleware whose `address` carries the query, which is also a security
property: a client cannot influence the auth hop's own parameters.