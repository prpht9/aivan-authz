# Phase E — put aivan-hud behind the gate

Status: complete (2026-11-13).

Standalone work file. Prerequisites: Phase D complete (a session can be minted
from a signed proof). Also needs `doc/traefik-contract.md` from Phase A for the
observed middleware behaviour.

Parent plan: `doc/aivan-initial-plan.md` §2, §8 Phase E. Spec:
`doc/aivan-initial-spec.md` §6.1, §8.1, §11 (acceptance 1, 3, 4, 10).

**Goal:** aivan-hud stops deciding who a request is. Traefik calls the gate, and
the application reads identity headers. A forged header cannot reach it, a
request without a proof never reaches it, and the public surface keeps serving
when the gate is down.

This phase is the only one that touches a second repository.

## E1. Two repositories, one cluster

- `aivan-authz` — the gate. Go. Distroless. Reachable only from Traefik.
- `aivan-hud` — the application. Ruby/Sinatra, chart in `k8s/`.

Repositories are separate. A change that spans both is two commits in two
repositories, in this order: gate first (it is additive and safe alone), then
application.

## E2. Routing

Replace hud's single ingress with three `IngressRoute` objects. Keep the Helm
chart's `templates/ingress.yaml` for the public router if it is easier, but the
gated router needs `middlewares`, which the stock `Ingress` kind cannot express,
so the gated router must be a `traefik.io/v1alpha1` `IngressRoute` regardless.
Put all three in one manifest so their priorities are visible together.

```yaml
# Order matters: Traefik evaluates by rule length, and the gate and public
# rules are longer than the catch-all, so they win without explicit priority.
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: aivan-hud-gate, namespace: aivan }
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`aivan-hud.home.arpa`) && PathPrefix(`/__aivan/`)
      kind: Rule
      services: [{ name: aivan-authz, port: 8080 }]
  tls: { secretName: aivan-hud-tls }
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: aivan-hud-public, namespace: aivan }
spec:
  entryPoints: [websecure]
  routes:
    - match: >-
        Host(`aivan-hud.home.arpa`) && (
          Path(`/`) ||
          Path(`/index.html`) || Path(`/hud-script.js`) ||
          Path(`/hud-style.css`) || Path(`/graph-data.js`) ||
          Path(`/chat`) || Path(`/chat/stream`) ||
          Path(`/speak`) || Path(`/transcribe`) || Path(`/hold`) ||
          Path(`/voices`) || Path(`/profiles`) ||
          Path(`/login`) || Path(`/register`) || Path(`/setup`)
        )
      kind: Rule
      services: [{ name: aivan-hud, port: 4700 }]
  tls: { secretName: aivan-hud-tls }
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata: { name: aivan-hud-gated, namespace: aivan }
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`aivan-hud.home.arpa`)
      kind: Rule
      middlewares:
        - name: aivan-auth
      services: [{ name: aivan-hud, port: 4700 }]
  tls: { secretName: aivan-hud-tls }
```

The public list above is derived from the routes in `aivan-hud/app.rb` plus the
four files in `viewer/`, which Sinatra serves from the root as a static folder.
`doc/auth.md` names the same set less precisely; this list is the one to keep in
step with the code, and the doc should be updated to match it in this phase.

Note `/login`, `/register` and `/setup` are public. They are the application's
own password flow, which the gate does not own. Once the gate is live they are
redundant for `/admin`, but removing them is an application decision and is
listed as still open in the parent plan. Leaving them public means a person can
still sign in to hud's own session, which grants nothing on gated routes because
`require_admin!` prefers the gate's header.

A route added to the app and not to this list lands on the gated router and
starts requiring a session, which is the failure mode called out in the parent
plan's risks.

`aivan-auth` middleware (`traefik.io/v1alpha1` `Middleware`):

```yaml
spec:
  forwardAuth:
    address: "http://aivan-authz.aivan.svc.cluster.local:8080/__aivan/verify"
    trustForwardHeader: false
    authResponseHeadersRegex: "^X-Aivan-"
    authRequestHeaders:
      - "X-Aivan-Device"
      - "X-Aivan-Nonce"
      - "X-Aivan-Signature"
      - "X-Aivan-Timestamp"
      - "Cookie"
      - "X-Aivan-Csrf"
    preserveRequestMethod: true
    forwardBody: true
    maxBodySize: 1048576
```

Values confirmed in Phase A; if Phase A found a different encoding or a
different failure status, this block is the place the correction lands.

Do **not** set `authSigninURL`. The gate returns its own `302` with `rd`.

One thing to confirm with `curl -v` against `/admin` after the cookie is set:
that the application still sees the correct scheme for `request.ssl?`. hud
already relies on Traefik setting `X-Forwarded-Proto`, and adding a
`forwardAuth` step should not change it. If it does, that is a finding for
`doc/traefik-contract.md`, not something to patch in the application.

## E3. The application reads headers

`aivan-hud/app.rb`. Replace `current_user` and `require_admin!`. Keep the
existing behaviour for the public surface intact.

```ruby
# Identity comes from the gate only. Never from a request header the application
# could receive from a client: Traefik strips ^X-Aivan- from client requests
# before forwardAuth runs, so these values are set by the gate or absent.
def gateway_identity
  return @gateway_identity if defined?(@gateway_identity)

  id = request.env['HTTP_X_AIVAN_USER_ID'].to_s
  @gateway_identity =
    if id.empty?
      nil
    else
      {
        id: id,
        username: request.env['HTTP_X_AIVAN_USER'].to_s,
        device_id: request.env['HTTP_X_AIVAN_DEVICE_ID'].to_s,
        roles: request.env['HTTP_X_AIVAN_ROLES'].to_s.split(',').reject(&:empty?),
        proof: request.env['HTTP_X_AIVAN_PROOF'].to_s,
        request_id: request.env['HTTP_X_AIVAN_REQUEST_ID'].to_s
      }
    end
end

def current_user
  return @current_user if defined?(@current_user)

  identity = gateway_identity
  # Public routes carry no identity header, so the cookie fallback stays for
  # them. On a gated route the header is authoritative and a cookie that
  # disagrees is ignored.
  @current_user =
    if identity && defined?(User)
      User.first(id: identity[:id].to_i)
    elsif !identity && defined?(User) && session[:user_id]
      User.first(id: session[:user_id])
    end
  @current_user = nil if @current_user && !@current_user.active
  @current_user
end

def require_admin!
  identity = gateway_identity
  if identity
    halt 403, { error: 'not an admin' }.to_json unless identity[:roles].include?('admin')
    return
  end

  # Public routes reach here only by a routing mistake; treat it as a denial.
  halt 401, { error: 'not signed in' }.to_json unless current_user
  halt 403, { error: 'not an admin' }.to_json unless current_user.admin?
end
```

Two deliberate choices:

- `require_admin!` prefers the header when present. Reading roles from the gate
  means the application cannot disagree with the gate about who is an admin.
- The cookie fallback survives for public routes. Removing it entirely would
  break `/setup` and `/register` on a development machine with no proxy.

Then delete the dev `header_auth_user` path or keep it behind
`DEV_HEADER_AUTH=1` and a non-production check. It reads
`HTTP_X_FORWARDED_USER`, which is not in `authRequestHeaders`, so through the
proxy it is always absent. Leave it, but add a comment saying it cannot fire
behind the gate.

`/admin` itself needs no change beyond `require_admin!`, which it already calls.

## E4. Logging

Log the gate's request id with denials, so an application error can be joined to
a gate decision:

```ruby
# in the before block, after the static-path check
env['aivan.request_id'] = request.env['HTTP_X_AIVAN_REQUEST_ID'].to_s
```

And include it in the 403 body for `/admin` refusals, since that is an operator
problem and not a secret. Do not log the identity headers on every request;
`X-Aivan-Roles` is not secret but it is not needed at that volume.

## E5. The gate's deployment

```yaml
# deploy/k8s.yaml in aivan-authz
apiVersion: apps/v1
kind: Deployment
metadata: { name: aivan-authz, namespace: aivan }
spec:
  replicas: 1
  selector: { matchLabels: { app: aivan-authz } }
  template:
    metadata: { labels: { app: aivan-authz } }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: authz
          image: docker.home.arpa:5000/aivan-authz:latest
          ports: [{ containerPort: 8080 }]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          env:
            - { name: AIVAN_LISTEN, value: ":8080" }
            - { name: AIVAN_HOSTS, value: "aivan-hud.home.arpa" }
            - { name: AIVAN_POLICY, value: "/etc/aivan/policy.yaml" }
            - name: AIVAN_DB_URL
              valueFrom:
                secretKeyRef: { name: aivan-authz-db, key: uri }
          readinessProbe:
            httpGet: { path: /readyz, port: 8080 }
            periodSeconds: 5
            failureThreshold: 3
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
            periodSeconds: 20
            failureThreshold: 6
          resources:
            requests: { cpu: 20m, memory: 32Mi }
            limits:   { memory: 128Mi }
          volumeMounts:
            - { name: policy, mountPath: /etc/aivan }
      volumes:
        - name: policy
          configMap: { name: aivan-authz-policy }
---
apiVersion: v1
kind: Service
metadata: { name: aivan-authz, namespace: aivan }
spec:
  selector: { app: aivan-authz }
  ports: [{ port: 8080, targetPort: 8080 }]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: aivan-authz-ingress, namespace: aivan }
spec:
  podSelector: { matchLabels: { app: aivan-authz } }
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
          podSelector: { matchLabels: { app.kubernetes.io/name: traefik } }
      ports: [{ port: 8080, protocol: TCP }]
```

Note: no `Ingress` or `IngressRoute` for the gate service. It is reached only by
the `forwardAuth` address and by the gate router on hud's host, both of which
resolve the cluster service directly. A `IngressRoute` for the gate on any host
would be a bypass.

Adjust the Traefik namespace/pod labels to what the cluster actually uses
(`kubectl -n kube-system get pods --show-labels`); the values above are the
common Helm defaults.

## E6. Testing without enrollment

Enrollment arrives in Phase F, so this phase needs a session from the console.

```text
authz dev-session --origin aivan-hud.home.arpa --kind browser --alg ed25519 \
  --username <name> --name "console test"
# prints a Set-Cookie value once, plus the device id
```

This subcommand is built with the `devtools` tag:

```go
//go:build devtools
```

so `go build ./cmd/authz` without the tag does not include it, and the image
never ships it. Phase F deletes it from the tree; until then it is the only way
to exercise the loop.

Use it with curl first, then a browser:

```bash
COOKIE=$(authz dev-session ... | grep Set-Cookie | cut -d' ' -f2)
curl -sk -b "$COOKIE" -D- https://aivan-hud.home.arpa/admin | head -20
```

## E7. Checklist

Done in `hermes-agent`, not `aivan`: Traefik refuses a Service named by an
IngressRoute in another namespace. See `doc/phase-e-record.md`.

- [x] Three routers applied; `kubectl -n hermes-agent get ingressroute` shows
      `aivan-hud-gate`, `aivan-hud-public` and `aivan-hud-gated`, plus the
      `aivan-auth` Middleware.
- [x] `/admin` with no cookie returns `302` to `/__aivan/enroll?rd=%2Fadmin`,
      and hud logs nothing, because it never received the request.
- [x] `/admin` with the console cookie returns the users table.
- [x] `/` returns the galaxy page with no cookie.
- [x] A forged `X-Aivan-User` and `X-Aivan-User-Id` sent to `/admin` are
      stripped: the response is the `302`, not a redirect loop and not the
      table. **Acceptance 4.**
- [x] The same forged headers with a valid cookie still yield the cookie's user.
- [x] The viewer assets load with no cookie: `/hud-script.js`,
      `/hud-style.css`, `/graph-data.js` all return `200` and not a `302`. These
      are the most likely breakage, because the galaxy page fetches them from
      the root and any one of them landing on the gated router blanks the page.
- [x] `/chat`, `/speak`, `/voices`, `/profiles`, `/hold` still work with no
      cookie.
- [x] `/login` still renders and `POST /login` still answers its own flow, and
      a `hud_session` cookie carrying a valid admin `user_id` does not open
      `/admin` while the gate is in front. A wrong password returns `401`
      rather than `login requires HTTPS`, which shows `request.ssl?` survives
      the new middleware hop.
- [x] Scale the gate to zero: `/admin` fails to reach the application (`500` in
      14 ms), `/` still renders. **Fail-closed and the public surface, spec
      §8.2.**
- [x] A curl pod in the namespace cannot reach the gate's cluster IP or its
      Service name (connection times out), while the same pod reaches hud
      normally. **Acceptance 10.**
- [x] A device enrolled for hud, presented to a second host behind the same
      gate, is refused with `session_invalid`. Proven with a second gate
      process on the same database, not a deployed second host; the deployed
      case stays with Phase G.
- [x] `X-Aivan-Proof` is `session` in hud's logs for a cookie request.

Also done, and not in the original list: `Accept` had to be added to the
middleware's `authRequestHeaders`, because without it the gate cannot choose
between the `401` and the `302` and acceptance 3 fails. See
`doc/phase-e-record.md` §3.

## E8. Exit criteria

- [x] Acceptance 1, 3, 4 and 10 hold, demonstrated with pasted output in
      `doc/phase-e-record.md`.
- [x] `aivan-hud/doc/auth.md` lists the same paths as the public router,
      including the viewer assets and the auth pages.
- [x] The gate has no `Ingress` and is unreachable from a pod.
- [x] Two commits: one in `aivan-authz` (deployment, roles, dev-session), one in
      `aivan-hud` (headers, routing, docs).
- [x] `aivan-hud/README_HOME_INSTALL.md` and `doc/auth.md` describe the three
      routers and the gate as a second service in the install.

## Handoff to Phase F

Phase F replaces the dev mint with real enrollment. It needs the gate router
(`/__aivan/`) working, which this phase proved, and it will add the
`enrollment` policy class.

Deliberate omission: no browser key generation yet, so the only way to get a
proof is a console command. That is a testing affordance, not a feature, and it
must not survive Phase F.

## Rollback

If the gate is wrong in a way that blocks work: delete the gated
`IngressRoute`, restore hud's original `Ingress` from
`k8s/templates/ingress.yaml`, and confirm `/admin` works on the cookie again.
The application change in E3 is backward compatible, so only routing needs
reverting.