# Phase D — sessions and CSRF

Standalone work file. Prerequisites: Phase C complete (signed proofs verify, one
statement per verify, denial matrix tested). No other phase file needed.

Parent plan: `doc/aivan-initial-plan.md` §5.5–§5.6, §8 Phase D. Spec:
`doc/aivan-initial-spec.md` §5.4, §9 (S5, S13).

**Goal:** after one signed proof, a browser carries a cookie instead of signing
every request; a revoke takes effect on the next request; and a cross-site POST
under that cookie is refused. One extra credential, no extra round trip.

## D1. What exists already

- `/__aivan/verify` consumes a nonce and returns the identity headers (C4).
- The denial helpers return byte-identical `401` bodies (C6).
- The pool is instrumented with a query counter (C4).

Sessions reuse all of that. The only new read is `authz.sessions`, already in the
schema from Phase B.

## D2. Minting

`POST /__aivan/session` — a signed proof, no cookie needed. Same headers as
verify, same signature check, same policy evaluation; the difference is the
response.

```text
token  = base64url(32 random bytes from crypto/rand)
stored = sha256(token)          -- the table never holds the token
```

Insert one row: `device_id`, `idle_expires_at = now()+IDLE`,
`absolute_expires_at = now()+MAX`. Then:

```text
Set-Cookie: __Host-aivan_session=<token>; Path=/; Secure; HttpOnly; SameSite=Lax
```

`__Host-` is load-bearing: it forbids `Domain`, so the cookie cannot leak to a
sibling host, which is exactly the per-origin model. Do not add `Domain`, do not
add `Max-Age` (server-side expiry is authoritative), and do not add
`SameSite=Strict` (a link from another site in the same browser should still
land signed in).

Response: `204` with the identity headers, or `200` with a small JSON body
listing expiry. Pick one and test it; `204` with headers is what Phase E expects.

This route must be reached through the gate's own router, not through
`forwardAuth`. Traefik does not deliver a cookie set on a forward-auth `200`
unless it is named in `addAuthCookiesToResponse`, and even then the request
would have been consumed as an auth check. Phase A recorded the observed
behaviour; the design does not depend on it.

Update `last_seen_at` on the device in the same statement as the insert. This is
the one write per session lifetime that keeps an operator able to answer "when
was this device last used" without a per-request write.

## D3. Reading the cookie

On `/__aivan/verify`, after the proof headers are found absent:

```sql
with touched as (
  update authz.sessions s
     set idle_expires_at = case
           when now() + $idle > s.idle_expires_at + interval '60 seconds'
           then now() + $idle else s.idle_expires_at end
   where s.token_hash = $1
     and s.idle_expires_at > now()
     and s.absolute_expires_at > now()
  returning s.device_id
)
select d.id, d.revoked_at, d.user_id, d.origin, d.kind,
       u.username, u.active,
       coalesce(array_agg(g.name order by g.name)
                filter (where g.name is not null), '{}') as roles
  from touched t
  join authz.devices d on d.id = t.device_id
  join public.users u  on u.id = d.user_id
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 group by d.id, d.revoked_at, d.user_id, d.origin, d.kind, u.username, u.active;
```

Three properties this buys:

- **Revoke is immediate (S5).** The join is through `devices`, so a revoked
  device yields a row whose `revoked_at` is set, and the check that follows
  denies. No second lookup, no waiting for expiry.
- **One round trip, same as a proof.** The session path does not cost more than
  the signature path.
- **The idle write is bounded.** The `case` pushes `idle_expires_at` forward only
  when it has moved more than 60 s, so a busy session writes once a minute at
  most and a quiet one writes never.

Keep both statements prepared. `$idle` is passed as an interval, not
interpolated.

`X-Aivan-Proof` is `session` on this path. The cookie value is never logged, and
the SQL above never returns it.

## D4. Policy and header differences

The session path does not skip policy. It runs the same C5 evaluation, so an
`admin` route needs `admin` in the roles either way.

Two differences from the proof path:

- `X-Aivan-Proof: session`.
- No `X-Aivan-Nonce`/`Signature` in the request, so CSRF applies (D5).

## D5. CSRF (S13)

Rule, applied only when the request authenticated by cookie:

- Safe methods (`GET`, `HEAD`, `OPTIONS`) pass.
- Unsafe methods require **either** `Sec-Fetch-Site: same-origin` or `none`,
  **or** an `X-Aivan-Csrf` header whose value matches `^[A-Za-z0-9_-]{16,128}$`.
- `Sec-Fetch-Site: same-site` is refused. Sibling subdomains are not the
  boundary we want, and the value is attacker-influenced only in the sense that
  a sibling host can produce it.
- Absent `Sec-Fetch-Site` (an old client, a non-browser, curl) falls back to the
  header requirement.

The reason a plain custom header is enough: a cross-origin HTML form cannot set
one, and a cross-origin `fetch` with a custom header triggers a preflight that
Traefik will not answer with permissive CORS. Confirm no CORS middleware is on
the gated router; if one is ever added, this rule weakens and must be revisited.

A request carrying a **signed proof** skips the check entirely, because the
signature covers the method, target and body. Mixed requests — cookie and proof
headers both present — are treated as proof. That is safe and avoids a client
having to do both.

## D6. Logout and revoke

`DELETE /__aivan/session` deletes the row for the presented cookie and returns
`204` with a `Set-Cookie` that clears it:

```text
__Host-aivan_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0
```

Idempotent: an unknown or absent cookie is still `204`. Logging out when you are
not signed in should not be an error.

Console commands:

```text
authz list-devices --username <name>
  id  origin  kind  name  alg  created  last_seen  revoked

authz revoke --device <uuid>
  in one transaction: set revoked_at = now(),
                      delete from authz.sessions where device_id = $1
  then: audit_log insert, print the count of sessions killed
```

Revoking by device, never by user, in v1. A user-level revoke would need a
policy about which devices survive, which is a later decision.

## D7. Tests

Integration, against the fixture database:

- [x] Mint requires a valid proof: no proof, bad signature, expired nonce all
      refuse and set no cookie.
- [x] The cookie has `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`,
      and no `Domain` and no `Max-Age`. Assert the whole header string.
- [x] A minted session authenticates `/__aivan/verify` with
      `X-Aivan-Proof: session` and the right user, device and roles.
- [x] The stored `token_hash` is not the token. Assert by value.
- [x] Idle expiry: past `idle_expires_at`, the session is refused (injected
      clock).
- [x] Absolute expiry: a session refreshed on activity still dies at
      `absolute_expires_at`.
- [x] **S5:** revoke a device, then present its live cookie — refused on the next
      request, with the same `401` body as an expired session.
- [x] **S13:** unsafe method with no `Sec-Fetch-Site` and no `X-Aivan-Csrf` —
      `403` with `reason=csrf_missing`. With `same-site` — `403`. With
      `same-origin` — allowed. With a valid `X-Aivan-Csrf` — allowed.
- [x] A request with both a cookie and a valid signed proof skips CSRF and
      reports `X-Aivan-Proof: nonce`.
- [x] Logout deletes the row and clears the cookie; a second logout is `204`.
- [x] **Query counter:** a session-authenticated verify is exactly one
      statement. Do not assert on database write counts; assert on the counter,
      which counts statements issued by the service. To prove the 60 s window
      works, assert the `idle_expires_at` value in the row is unchanged after a
      verify 30 s later, and changed after one 90 s later.
- [x] Revoke kills sessions in the same transaction: kill the process between
      the two statements in a test build and assert the database has neither a
      live device nor a live session.

Every item marked S5 or S13 must be shown to fail without its guard. The
removal table is in `doc/phase-d-record.md`.

## D8. Exit criteria

- [x] S5 and S13 green and demonstrated to fail without their guards.
- [x] One statement per session-authenticated request, asserted.
- [x] Cookie header asserted as a full string, not by substring.
- [x] Revoke is transactional and tested across a mid-flight crash.
- [x] Commit.

The verification record is `doc/phase-d-record.md`.

## Handoff to Phase E

Phase E puts aivan-hud behind the gate and needs a session mint to test the
proxy loop end to end. It uses `POST /__aivan/session` with a dev device, which
is why this phase lands before enrollment exists.

Deliberate omission: no enrollment, so there is no browser-native way to obtain
a proof yet. Phase E mints one from the console.