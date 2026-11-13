# Design notes

Working notes from the conversation that produced
`doc/aivan-initial-spec.md`. These record the reasoning, the options that were
rejected, and the traps found along the way. They are not requirements; the
specification is. Where a note contradicts the spec, the spec wins.

## 1. The question that started it

The original question was whether the aivan-hud web page should allow a login
at all, or whether authentication should happen only from the phone app.

The reframe that settled it: **two mechanisms were being conflated.**

- The phone key proves *who is acting* and, more importantly, records
  *consent* to a specific action.
- A browser session proves *which tab is open*.

They are different jobs. The consequence: the browser session is fine for
reading and for low-privilege use, and a phone signature is what grants
authority.

Later, the same distinction reappeared as the mTLS versus signed-nonce
question, and it resolved the same way. A TLS handshake proves *who connected*.
A signature proves *what they agreed to*. Approvals need the second one, and
mTLS can never supply it. That is why grants, not certificates, are the core
artifact.

## 2. How aivan-hud got here

Before the proxy gate existed, aivan-hud had a working but narrow auth story:

- `users`, `groups`, `groups_users`, bcrypt at cost 12, admin defined as
  membership in the `admin` group.
- `Galaxy::Accounts.setup_open?` returned true while no admin existed, and the
  `admin` group row was locked with `SELECT … FOR UPDATE` so two concurrent
  creates could not both win.
- Two bootstrap paths: a loopback `/setup` form for development, and
  `rake admin:create` inside the pod.

Three defects were found by testing the running install rather than reading the
code:

1. **The login cookie was never stored.** The cookie was marked `Secure` in
   production while the ingress served plain HTTP, so the browser dropped it.
   `POST /login` returned `200` with no `Set-Cookie`. Fixed by refusing
   plaintext login with a clear message and adding TLS to the ingress.
2. **`/setup` was reachable inside the pod.** A `kubectl port-forward` arrives
   at the pod from `127.0.0.1`, so the loopback peer check could not tell a
   developer from anyone holding `kubectl`. Fixed by closing the form whenever
   `RACK_ENV=production`.
3. **Sessions died on every restart** because `SESSION_SECRET` was unset and
   the app invented a secret at boot. Fixed with a chart-managed secret.

A fourth, embarrassing one: `/login` and `/register` were JSON-only routes with
no `get` handler, so a browser tab got a 404. There was no sign-in page at all
and no link to one. Two real pages were added, plus a form/JSON content-type
split so the API is unchanged.

The lesson worth carrying into aivan-authz: **every one of these was found by
exercising the real flow, and none by reading the code.** The spec's section 9
requirements exist so each one has a test that fails when the requirement is
removed.

## 3. The sequence, and the bug in it

The operator's proposed sequence was:

1. start everything
2. `rake admin:create`
3. phone registration with password
4. phone gets mTLS working
5. desktop browser registers as an mTLS client for the same admin
6. phone approves

The bug: "then password access should be disabled, permanently" was placed
between the key upload and the first successful TLS handshake. If the upload
succeeds and the handshake then fails, the system has no working credential at
all.

The fix is a rule:

> The bootstrap password is retired only when a device has **signed a
> server-issued challenge**. A public key upload is an intent; a verified
> signature is proof.

That keeps a failed enrollment retryable and makes the transition safe. It is
requirement S12 and section 5.3.

## 4. The mTLS question, revisited

The operator asked whether Linux was the only platform where client
certificates are awkward, and whether this had to be solved now.

Answer: no, it is awkward everywhere, and it does not need solving now.

The keystore story per platform:

| Platform | Where the key must live | Friction |
|---|---|---|
| Chrome on Windows | Windows cert store | `.p12` import in `certmgr.msc` |
| Chrome or Safari on macOS | Login keychain | `.p12` double-click, then a picker |
| Chrome on Linux | NSS database in `~/.pki/nssdb` | `pk12util`, CLI-heavy |
| Firefox on any platform | Its own NSS store | A second import, always |
| Safari on iOS | Device profile | Two Settings trips, plus trust settings |
| Chrome on Android | System keystore | Settings → Security → credentials |

Two consequences:

- Firefox ignores the OS store on every platform, so a Firefox user imports
  twice.
- Once imported, the key is exportable. That defeats the point of a hardware
  key.

So the decision was to make **signed nonces primary** and mTLS an optional
per-device upgrade. `devices.proof` records which mechanism a device uses, so
both can coexist without a second table or a second code path.

The one thing mTLS still gives that nonces do not:

- Edge rejection, before the app does work. This is blast radius, not auth.
- No per-request verification code in the service, so no route can forget it.
- Channel binding to the TLS session.

The last one is why the spec requires the nonce to be bound to the request
(method, host, path, body hash, nonce, timestamp) rather than signing the nonce
alone. A signature over the whole canonical string cannot be relayed to a
different request.

## 5. Where to put the CA

The operator asked whether the root should be an offline root on a USB stick in
a fireproof safe, and which of the Pi or the compute server is more likely to
be compromised first.

Reasoning:

- **The Pi is more exposed.** It is the network edge: firewall, VPN, haproxy,
  reachable from the home wifi. It has the remote attack surface.
- **The compute server is more valuable.** It holds Postgres, the session
  secret, the database credential, and the model API keys.

Then the decisive point: **the verifier lives on the compute server.** Device
authentication is decided by code reading `devices` rows in the database on
that box. An attacker who owns the compute server inserts a device row and
never touches a certificate. An offline root protects against certificate
forgery, and that threat is moot when the same attacker controls the verifier.

Conclusions recorded in the spec:

- No client CA at all. Device certificates, if used, are self-signed and pinned
  by fingerprint. The database is the trust store.
- A house CA on the compute server is fine for the **ingress server
  certificate** only. Compromise means someone can mint a certificate for
  `aivan-hud.home.arpa`, and the fix is to re-issue and redistribute `ca.crt`.
- The fireproof-safe root is the right pattern for a real PKI with an
  independent verifier. This system does not have one.

## 6. Forward auth as the enforcement point

The operator had built proxy-level auth before (Apache `authz`, Emissary
`AuthService`) and wanted the same pattern here.

Traefik has `forwardAuth`, and the cluster already supports it: the
`middlewares.traefik.io` CRD is present, and both `kubernetescrd` and
`kubernetesingress` providers are enabled on Traefik 3.7.13. No upgrade needed.

The config that makes the headers trustworthy:

- `authResponseHeadersRegex: "^X-Aivan-"` — and the important part is that this
  **strips matching headers from the incoming client request first**, then
  copies them from the auth service's response. That is what makes a
  client-supplied `X-Aivan-User` impossible.
- `trustForwardHeader: false` — otherwise a client-supplied `X-Forwarded-For`
  reaches the auth service and any IP-based rule becomes fiction.
- `authRequestHeaders` — an explicit list, so the service sees only the device
  proof headers, the cookie, and nothing else.
- Entrypoint `aliasHeadersStrategy: delete` (or `reject`) — Go treats
  `X-Aivan-User` and `X_Aivan_User` as different headers, and some backends
  normalize them. Traefik warns while this is left at `keep`.

Notes from the predecessor that carry over: `van-auth` ran behind Emissary with
a 5000 ms timeout, `status_on_error: 403`, and `failure_mode_allow: false`.
The failure posture in the spec (fail closed, public surface outside the chain)
is the same idea.

## 7. The two traps in the first version

**Latency is not the hard part; the failure mode is.** If the auth service is
down or slow, every protected request stalls or fails. So:

- Keep the galaxy page and its static assets off the auth chain, so an auth
  outage does not blank the whole application.
- Set an explicit timeout in Traefik, shorter than the slowest acceptable wait.
- Fail closed on protected routes.

**CSRF becomes real the moment there is a cookie.** A browser session cookie is
sent by cross-site requests too. mTLS or a device proof authenticates the
request but does not prove intent. The spec requires a CSRF token or a required
custom header on every state-changing request under a cookie (S13). This is the
most likely bug in a first implementation.

A useful asymmetry: a request carrying a signed device proof and no cookie
needs no CSRF defense, because the signature covers the intent. Only the cookie
path needs it.

## 8. Data model reasoning

The operator expects many devices per user — phones, tablets, several
computers. "Not 25, but definitely more than one."

So: one row per device, never one column per user, and no practical cap.

Three details that pay off later:

- **The device id is a UUID and is the certificate subject**, not a username.
  Renaming a user or changing an email cannot break authentication, and a
  certificate does not advertise who the person is.
- **`revoked_at` exists from the first migration**, even though disaster
  recovery is explicitly deferred. A nullable column now costs nothing and
  saves a migration later.
- **`proof` is per device**, which is what lets phone mTLS and browser nonces
  share one table and one lookup path.

## 9. Enrollment without an authenticated browser

The browser has no credential before it is enrolled. That is fine as long as
identity comes from somewhere else.

The rule: the claiming device does not assert who it is. The **pending
enrollment** record names the user, and the claim binds to that record.

Two failure modes this closes:

- **Front-running.** An attacker who can reach the enrollment endpoint submits
  their own key first and takes the pending record. Closed by requiring the
  short code that the phone displayed, and requiring it inside the signed
  approval when a signature is used.
- **Confused approval.** The user taps "approve" on the phone for a request
  they are not actually looking at. Closed by the same code binding: the code
  the browser shows must appear in what the phone signs.

The operator's idea of a preemptive "I am about to register a device" from the
phone is exactly this pending record, and it makes open registration a non-issue
because there is nothing to claim without one.

## 10. Registration versus bootstrap versus enrollment

Three events were previously smeared into one:

| Event | Creates | Source of truth | Frequency |
|---|---|---|---|
| Bootstrap | Authority (admin group) | Console on the compute server | Once, ever |
| Registration | An identity claim, no groups | Web or phone | Per person |
| Enrollment | A bound device key | Phone approval | Per device |

Answering the operator's question directly: **the admin does not need to
register over and above setup.** Bootstrap already produces a complete,
verified admin in the `admin` group. Re-registering would be rejected by the
unique constraint on email and username. What the admin needs is enrollment,
which is a different step with a different purpose.

The `verified` column in aivan-hud currently distinguishes "an admin typed this
row" from "a stranger typed this row," and nothing else consumes it. Its useful
future meaning is *an approver vouched for this identity*, optionally with a
bound device. That belongs to registration policy, which is a later decision.

## 11. Language: Ruby or Go

The measured cost of `van-auth` in Ruby was already acceptable, so latency is
not the deciding factor. The real differences:

- Go ships one static binary, no interpreter to patch, and no gem drift.
- Ruby reuses existing skill and the existing test harness (`cucumber`,
  `rack-test`).

The spec leaves this open with a lean toward choosing on operational grounds.
The author's note: Go is the better fit for a single shipped binary in a home
install where nobody wants to patch a runtime; Ruby is fine if speed of change
matters more. Either way the decision path is one database read, and that is
the same in both.

## 12. Things explicitly deferred

Recorded so they are not rediscovered as surprises:

- **Disaster recovery and lost phones.** `revoked_at` exists; the procedure does
  not.
- **mTLS for any device.** Optional, per device, later.
- **Push notifications to the phone.** The phone polls or is invoked. Home
  installs have no reliable cloud push and possibly no clock sync.
- **Second admin, or demoting one.** Console work.
- **Registration policy for other people.** Invite grants from the phone are
  the natural answer, but it is a separate decision from the admin's own
  devices.
- **Certificate renewal** for the ingress server certificate.

## 13. Test lessons to carry over

From the aivan-hud work, worth stating as a habit:

- A screenshot of the first frame verifies nothing. Exercise the flow.
- Test the path with the *old* credential after switching mechanisms, because
  that is where the silent failure lives.
- Test the plaintext route, not just the TLS route.
- Test with the proxy in front, because `X-Forwarded-Proto`, `REMOTE_ADDR`, and
  the cookie `Secure` flag all behave differently behind a terminator than they
  do against a bare app.
- Verify the *absence* of a header as carefully as its presence. A missing
  `Set-Cookie` looked like a success until the next request.

## 14. Rejected options, with reasons

| Rejected | Why |
|---|---|
| Offline root CA in a safe | The verifier is on the same host the root would protect |
| A CA for client certificates | Device rows are the trust store; a CA adds a key without adding a boundary |
| One shared browser certificate for everyone | The system would no longer know who asked |
| Verifying client certificates inside the application as well as at the proxy | Two trust stores, no added assurance |
| Requiring a client certificate for the public galaxy API | Locks users out of the page before they can enroll |
| Treating `X-Forwarded-User` as identity | A dev stand-in, not a credential |
| Disabling the password before the first signature | Can brick the install on a failed enrollment |
| Password as a permanent second factor | The operator's stated intent is to retire it |
| Global auth policy | Per-route policy is what lets the public page stay reachable during an auth outage |
