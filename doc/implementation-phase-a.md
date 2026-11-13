# Phase A — prove the Traefik contract

Standalone work file. Read this and `doc/aivan-initial-spec.md` §8.1 only; no
other phase file is a prerequisite. Parent plan: `doc/aivan-initial-plan.md` §8,
Phase A.

**Goal:** turn three documented Traefik behaviours into observed ones *before*
any gate code depends on them. This phase writes no gate code. Its output is
`doc/traefik-contract.md`, a record of what the cluster actually does.

**Why this is first:** the whole design rests on `X-Forwarded-Uri` being
reproducible, on a non-2xx response reaching the client intact, and on cookies
not being forwarded implicitly. Each is cheap to confirm now and expensive to
discover inside a signature-verification failure later.

## Preconditions

- Cluster reachable with `kubectl`, Traefik 3.7.13 serving `*.home.arpa`.
- `middlewares.traefik.io` CRD present.
- A spare hostname. `aivan-echo.home.arpa` for the rest of this document.
- TLS for that hostname, or a browser that will accept the self-signed CA from
  `README_HOME_INSTALL.md`. `Set-Cookie; Secure` needs HTTPS to be observable.

## A1. The echo service

One file, no dependencies, no build step worth managing. It prints what it
received as JSON and lets you command its auth response.

Ruby 4.0 removed WEBrick from the standard library, so this uses `TCPServer`
directly. That keeps the no-dependency property and costs about eighty lines.

```ruby
# /tmp/echo/echo.rb
# Echo/probe service for the Traefik forwardAuth contract.
# One process, two roles: /auth for forwardAuth, everything else as backend.
# Ruby 4.0 dropped WEBrick from the stdlib, so this uses TCPServer directly to
# keep the "no dependencies, no build step" property of the plan.
#
# Auth response modes are chosen by the query string on the middleware's
# address, because Traefik calls the address verbatim and never appends the
# client's query string:
#   ?mode=ok             200 + identity headers + a Set-Cookie probe
#   ?mode=redirect       302 to /__aivan/enroll
#   ?mode=deny           401 with WWW-Authenticate and a JSON body
#   ?mode=fail           500
#   ?mode=slow&secs=30   sleeps, then 200 — for measuring the auth timeout
#
# Every auth response also carries X-Aivan-Auth-* describing what the auth hop
# received, so those values can be read back from the client even on a HEAD.

require 'json'
require 'socket'
require 'digest'

PORT = 8080

REASONS = {
  200 => 'OK', 302 => 'Found', 401 => 'Unauthorized',
  404 => 'Not Found', 500 => 'Internal Server Error'
}.freeze

def read_exact(sock, n)
  buf = +''
  while buf.bytesize < n
    chunk = sock.read(n - buf.bytesize)
    break if chunk.nil?

    buf << chunk
  end
  buf
end

def read_request(sock)
  line = sock.gets("\r\n")
  return nil if line.nil?

  method, target, = line.strip.split(' ', 3)
  headers = {}
  while (h = sock.gets("\r\n"))
    h = h.chomp("\r\n")
    break if h.empty?

    k, v = h.split(':', 2)
    next if v.nil?

    (headers[k.strip.downcase] ||= []) << v.strip
  end

  body = +''
  if headers['transfer-encoding']&.first&.downcase&.include?('chunked')
    loop do
      size = (sock.gets("\r\n") || '0').strip.split(';').first.to_i(16)
      break if size.zero?

      body << read_exact(sock, size)
      sock.read(2)
    end
  elsif (cl = headers['content-length']&.first)
    n = cl.to_i
    body << read_exact(sock, n) if n.positive?
  end

  [method, target, headers, body]
end

def write_response(sock, status, headers, body)
  head = +"HTTP/1.1 #{status} #{REASONS.fetch(status, 'Unknown')}\r\n"
  headers.each { |k, v| head << "#{k}: #{v}\r\n" }
  head << "Content-Length: #{body.bytesize}\r\n"
  head << "Connection: close\r\n\r\n"
  sock.write(head)
  sock.write(body) unless body.empty?
end

def parse_query(query)
  return {} if query.nil? || query.empty?

  query.split('&').each_with_object({}) do |pair, acc|
    k, v = pair.split('=', 2)
    acc[k] = v.to_s
  end
end

# What the auth hop received. Those keys are covered by the signature, so their
# exact values matter as much as the backend's.
def auth_dump(req)
  h = ->(name) { req[:headers][name]&.first.to_s }
  {
    'X-Aivan-Auth-Method'   => h.call('x-forwarded-method'),
    'X-Aivan-Auth-Proto'    => h.call('x-forwarded-proto'),
    'X-Aivan-Auth-Host'     => h.call('x-forwarded-host'),
    'X-Aivan-Auth-Uri'      => h.call('x-forwarded-uri'),
    'X-Aivan-Auth-ReqMethod' => req[:method],
    'X-Aivan-Auth-Query'    => req[:query].to_s,
    'X-Aivan-Auth-BodyLen'  => req[:body].bytesize.to_s,
    'X-Aivan-Auth-Headers'  => req[:headers].keys.sort.join(',')
  }
end

def auth_response(req)
  mode = req[:params]['mode'] || 'ok'
  ident = {
    'X-Aivan-User'    => 'from-auth',
    'X-Aivan-User-Id' => '42',
    'X-Aivan-Roles'   => 'admin,free'
  }
  cookie = {
    'Set-Cookie' => 'aivan_session=probe; Path=/; Secure; HttpOnly; SameSite=Lax'
  }

  case mode
  when 'redirect'
    [302, auth_dump(req).merge('Location' => '/__aivan/enroll?rd=%2Fadmin'), '']
  when 'redirectcookie'
    [302, auth_dump(req).merge('Location' => '/__aivan/enroll?rd=%2Fadmin').merge(cookie), '']
  when 'deny'
    [401, auth_dump(req).merge('WWW-Authenticate' => 'Aivan'), '{"error":"no proof"}']
  when 'fail'
    [500, {}, 'auth exploded']
  when 'slow'
    sleep(req[:params].fetch('secs', '10').to_i)
    [200, auth_dump(req).merge(ident), '']
  else
    [200, auth_dump(req).merge(ident).merge(cookie), '']
  end
end

def handle(sock)
  req = read_request(sock)
  return if req.nil?

  method, target, headers, body = req
  path, query = target.to_s.split('?', 2)
  req = { method: method, target: target, path: path, query: query,
          headers: headers, body: body, params: parse_query(query) }

  if path == '/auth'
    status, resp_headers, resp_body = auth_response(req)
    write_response(sock, status, resp_headers, resp_body)
    return
  end

  out = {
    method: method,
    path: path,
    query: query.to_s,
    target: target,
    headers: headers.transform_values { |v| v.join(', ') },
    body_len: body.bytesize,
    body_sha256: Digest::SHA256.hexdigest(body)
  }
  write_response(sock, 200, { 'Content-Type' => 'application/json' },
                 JSON.pretty_generate(out))
rescue StandardError => e
  warn "echo error: #{e.class}: #{e.message}"
  begin
    write_response(sock, 500, {}, e.message)
  rescue StandardError
    nil
  end
ensure
  begin
    sock.close
  rescue StandardError
    nil
  end
end

server = TCPServer.new('0.0.0.0', PORT)
warn "echo listening on #{PORT}"

loop do
  client = server.accept
  Thread.new(client) { |c| handle(c) }
end
```

The auth response mode comes from the query string on the **middleware
address**, not the client's URL, because Traefik calls the address verbatim and
never appends the client's query. Modes: `ok` (200 with identity headers and a
`Set-Cookie` probe), `redirect` (302), `deny` (401 with a body and
`WWW-Authenticate`), `fail` (500), `slow&secs=N` (sleep then 200), and
`redirectcookie` (302 carrying a cookie, for the cookie-on-redirect check).

Every auth response also carries `X-Aivan-Auth-*` describing what the auth hop
received, and `authResponseHeadersRegex: "^X-Aivan-"` copies those to the
client. That is how the forwarded values are read back without a second
endpoint — including on a `HEAD`, whose response has no body.

Run it as a pod and a service:

```yaml
# /tmp/echo/k8s.yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: echo-src, namespace: aivan }
data:
  echo.rb: |
    <paste the file above>
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: echo, namespace: aivan }
spec:
  replicas: 1
  selector: { matchLabels: { app: echo } }
  template:
    metadata: { labels: { app: echo } }
    spec:
      containers:
        - name: echo
          image: ruby:4.0.5-slim-trixie
          command: ["ruby", "/src/echo.rb"]
          ports: [{ containerPort: 8080 }]
          volumeMounts: [{ name: src, mountPath: /src }]
      volumes:
        - name: src
          configMap: { name: echo-src }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: aivan }
spec:
  selector: { app: echo }
  ports: [{ port: 8080, targetPort: 8080 }]
```

The TLS secret the `IngressRoute` references has to exist before the router is
useful. A two-minute self-signed certificate for the probe host is enough,
because every request uses `curl -k`:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout /tmp/echo/k.pem -out /tmp/echo/c.pem \
  -subj "/CN=aivan-echo.home.arpa" \
  -addext "subjectAltName=DNS:aivan-echo.home.arpa"
kubectl -n aivan create secret tls aivan-echo-tls \
  --cert=/tmp/echo/c.pem --key=/tmp/echo/k.pem
```

## A2. The middleware under test

```yaml
# /tmp/echo/middleware.yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata: { name: aivan-auth-probe, namespace: aivan }
spec:
  forwardAuth:
    address: "http://echo.aivan.svc.cluster.local:8080/auth"
    trustForwardHeader: false
    authResponseHeadersRegex: "^X-Aivan-"
    authRequestHeaders:
      - "X-Aivan-Device"
      - "X-Aivan-Nonce"
      - "X-Aivan-Signature"
      - "X-Aivan-Timestamp"
      - "Cookie"
    addAuthCookiesToResponse:
      - "aivan_session"
    preserveRequestMethod: true
    forwardBody: true
    maxBodySize: 1048576
    preserveLocationHeader: true
```

`preserveLocationHeader` is in the block because Phase A found it is required:
without it a `302` from the auth service reaches the browser with `Location`
pointing at the auth service's cluster address. See
`doc/traefik-contract.md`.

An `IngressRoute` that puts the middleware on the gated router. A relative
`Location` still needs a TLS certificate the client will accept; generate a
self-signed one for the probe host rather than borrowing another host's secret,
because `--resolve` plus a matching SAN is simpler to reason about than a
mismatch:

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: echo-probe, namespace: aivan }
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`aivan-echo.home.arpa`) && PathPrefix(`/auth`)
      kind: Rule
      services: [{ name: echo, port: 8080 }]
    - match: Host(`aivan-echo.home.arpa`)
      kind: Rule
      middlewares: [{ name: aivan-auth-probe }]
      services: [{ name: echo, port: 8080 }]
  tls:
    secretName: aivan-echo-tls
```

The `/auth` route sits above the gated route so the echo pod can be driven
directly in its auth role without a second deployment.

**Read this before writing the checklist commands.** Traefik calls the
middleware `address` verbatim and does **not** append the client's query string,
so `?mode=deny` on the client's URL never reaches the auth service. Each auth
response mode needs its own middleware whose `address` carries the query:

```yaml
# One per mode: deny, redirect, slow, fail.
spec:
  forwardAuth:
    address: "http://echo.aivan.svc.cluster.local:8080/auth?mode=deny"
```

paired with its own host and router. That is also why no client input can steer
the auth hop's parameters — a property worth keeping.

If the probe hostname has no DNS record, use
`curl --resolve aivan-echo.home.arpa:443:192.168.192.2` on every request rather
than editing `/etc/hosts`.

## A3. Checklist

Run each check and paste the observed output into `doc/traefik-contract.md`.
`curl -k` is fine; browser checks need a trusted certificate.

### Header strip (S6)

```bash
curl -sk https://aivan-echo.home.arpa/one \
  -H 'X-Aivan-User: attacker' -H 'X-Aivan-User-Id: 1' | jq .headers
```

- [x] `X-Aivan-User` in the output is `from-auth`. (`attacker` never arrived.)
- [x] `X-Aivan-User-Id` is `42`. (`1` never arrived.)
- [x] Record the exact output. This is the one result the whole trust model
      rests on.

Observed: `{"x-aivan-roles": "admin,free", "x-aivan-user": "from-auth",
"x-aivan-user-id": "42"}`. An injected `X-Aivan-Extra` was absent too, because
the auth response did not set it, so the regex removes every matching header and
restores only what the auth response returns.

Then with the middleware removed, confirm the client value *does* arrive
untouched. A strip that cannot be shown to strip is not a strip.

Observed with no middleware: `{"x-aivan-roles": "root", "x-aivan-user":
"attacker", "x-aivan-user-id": "1"}`.

### Non-2xx passthrough

```bash
# Each mode needs its own middleware whose address carries ?mode=...
# See the note in A2.
curl -sk -o /dev/null -D- https://echo-deny.home.arpa/one
curl -sk -o /dev/null -D- https://echo-redirect.home.arpa/one
```

- [x] The `401` arrives with body `{"error":"no proof"}` and the
      `WWW-Authenticate` header.
- [x] The `302` arrives with `Location: /__aivan/enroll?rd=%2Fadmin` unmodified
      **only with `preserveLocationHeader: true`**, and curl does not follow it
      (`-o /dev/null -D-`). Without the option `Location` becomes
      `http://echo.aivan.svc.cluster.local:8080/__aivan/enroll?rd=%2Fadmin`.
- [x] Record whether Traefik rewrote either status. Neither status is rewritten:
      `401` and `302` arrive as sent. Only `Location` is rewritten, and the
      option prevents that.

Where the auth response's `X-Aivan-*` headers go depends on the status: on a 2xx
they are copied onto the request forwarded to the backend and the client never
sees them; on a non-2xx the auth response *is* the client's response, so its
headers reach the browser. The gate must therefore set no identity header on a
denial or a redirect.

### Cookie forwarding

```bash
curl -sk -o /dev/null -D- https://aivan-echo.home.arpa/one | grep -i set-cookie
```

- [x] With `addAuthCookiesToResponse` present, `aivan_session` reaches the
      client: `aivan_session=probe; Path=/; HttpOnly; Secure; SameSite=Lax`
      (Traefik reorders the attributes and keeps the values).
- [x] Comment it out, re-apply, repeat. Without it there is no `Set-Cookie` at
      all.
- [x] This decides nothing in the design — session minting is already a
      dedicated route — but the plan asserts the behaviour, so confirm it. It
      holds. A `302` carrying `Set-Cookie` also delivers both header and cookie,
      so mint-on-redirect would work if it were ever wanted.

### Forwarded values

```bash
curl -sk 'https://aivan-echo.home.arpa/a%20b?x=1&y=%2F' | jq '.headers | with_entries(select(.key|test("X-Forwarded")))'
```

- [x] Record `X-Forwarded-Method`, `-Proto`, `-Host`, `-Uri` verbatim: `GET`,
      `https`, `aivan-echo.home.arpa`, `/a%20b?x=1&y=%2F`.
- [x] `X-Forwarded-Uri` is `/a%20b?x=1&y=%2F`, byte for byte, and the encoding
      is not normalised for that input.
- [x] Repeat with `-X POST -d 'hello'` and confirm `X-Forwarded-Method` is
      `POST`. It is, and the body reaches the auth hop in full (5 bytes,
      `sha256 = 2cf24dba...`).
- [x] `X-Forwarded-Port` (`443`) and `X-Real-Ip` appear, both injected by
      Traefik and not suppressible.

**This box does not survive the general case.** The plan's sample target is
preserved because `%20` and `%2F` are reserved characters. Percent-encoded
*unreserved* characters are decoded by the entrypoint before routing, and hex
digits are uppercased: `/%41` → `/A`, `/%7Euser` → `/~user`, `/a%2Eb` → `/a.b`,
`/%2f` → `/%2F`. Duplicate slashes and dot-segments are collapsed too. The query
string is preserved exactly in every case tried. The browser's
`location.pathname` keeps the client's form, so those inputs cannot be verified.
Recorded as a contradiction and corrected in the plan and spec; Phase C's
vectors use only characters that survive normalisation.

### Auth service down

```bash
kubectl -n aivan scale deploy echo --replicas=0
curl -sk -o /dev/null -D- --max-time 10 https://aivan-echo.home.arpa/one
kubectl -n aivan scale deploy echo --replicas=1
```

- [x] The client sees `500` with an empty body. Spec §8.2 requires a refusal;
      this is one.
- [x] Time it. Unreachable: 14 ms. Hanging auth service: 30.01 s, then `500`.

The finding is worth stating plainly: **`forwardAuth` has a hardcoded 30 s
timeout and no configuration field for it**, and `ServersTransport` does not
apply to the auth call. A gate with a shorter internal deadline is the only way
to keep the user's wait under 30 s. Spec §8.2 corrected accordingly.

### Body size

```bash
head -c 2000000 /dev/zero | tr '\0' 'a' > /tmp/big.txt
curl -sk -o /dev/null -D- -X POST --data-binary @/tmp/big.txt \
  https://aivan-echo.home.arpa/one
```

- [x] `401`, empty body, no `WWW-Authenticate`, in 10 ms. The boundary is exact:
      1048576 bytes is allowed, 1048577 is refused. Told apart from the gate's
      `413` by the status, though both mean "the body was not verified".

## A4. Write the record

`doc/traefik-contract.md`:

```markdown
# Traefik forwardAuth contract, as observed

Cluster: <version>, Traefik <version>, entrypoint <name>.
Probe: aivan-echo.home.arpa, middleware aivan-auth-probe.
Date: <date>. All output below is verbatim.

## Header strip
## Non-2xx passthrough
## Cookie forwarding
## Forwarded values
## Auth service down
## Body size

## Conclusions
- X-Forwarded-Uri reproducible? <yes/no, with the encoding caveat>
- 302 reachable with Location intact? <yes/no>
- Cookie needs addAuthCookiesToResponse? <yes/no>
- Status when auth is unreachable: <n>
- Anything that contradicts doc/aivan-initial-plan.md §2 or §5.1: <none | list>
```

## A5. Exit criteria

- [x] Every box in A3 ticked, with pasted output.
- [x] `doc/traefik-contract.md` exists and states the five conclusions.
- [x] Any contradiction with the plan is written down, and the plan and spec are
      corrected rather than deferred. Two contradictions were found (path
      normalisation, `Location` rewriting) and two further observations were
      recorded (the hardcoded 30 s timeout, and that
      `authResponseHeadersRegex` does not strip the request to the auth hop).
      The spec is now revision 3 with amendments A22 and A23.
- [x] All probe resources deleted, and the host stops responding: after teardown
      `https://aivan-echo.home.arpa/one` returns Traefik's bare `404` and the
      `aivan` namespace holds only its `kube-root-ca.crt`.

## What this phase does not do

No gate code, no schema, no Postgres. If a check fails, this phase is not
complete; the fix belongs to the document, not to a workaround in a service that
does not exist yet.

## Handoff to Phase B

Phase B starts from an empty `aivan-authz` tree. It needs nothing from this
phase except the conclusion on `X-Forwarded-Uri` encoding, which it encodes as
a test vector. Leave `doc/traefik-contract.md` in place; Phase E reads it when
wiring aivan-hud.

The vectors that matter, from `doc/traefik-contract.md`:

- Safe to sign and verify: literal `a-z A-Z 0-9 - . _ ~`, space as `%20`, and
  `/` in the query as `%2F`. The querystring survives byte for byte, including
  lower-case hex and `&&`.
- Refused by design, because Traefik decodes or re-cases them: `%41`, `%7E`,
  `%2E`, and lower-case hex such as `%2f`. A vector using these must assert a
  refusal, not a success.
- The gate compares verbatim. It never normalises the client's string to match
  `X-Forwarded-Uri`, because that would let two client strings collide on one
  target.

Two configuration facts Phase B and E must carry forward:
`preserveLocationHeader: true` on the gate's middleware, and a request deadline
inside the service well under Traefik's hardcoded 30 s auth timeout.