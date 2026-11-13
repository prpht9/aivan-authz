# Phase C — proof, policy, and the hot path

Standalone work file. Prerequisites: Phase B complete (binary starts, schema
applied, privilege probe passing). No other phase file needed.

Parent plan: `doc/aivan-initial-plan.md` §5.1–§5.4, §5.8, §7, §8 Phase C. Spec:
`doc/aivan-initial-spec.md` §5.1, §5.1.1, §6.1, §6.2, §9 (S1–S4, S7, S8, S14,
S15, S17, S19, S21).

**Goal:** a nonce-verified request produces identity headers in one database
round trip, and every denial reason is covered by a test that fails when the
guard is removed. Sessions do not exist yet; a signed proof is the only way in.

## C1. Canonical string

`internal/proof/canonical.go`. The string is shared with the browser, so it is
specified once and tested against fixed vectors.

```text
aivan-v1 \n
METHOD \n
SCHEME://HOST \n
REQUEST-TARGET \n
SHA256(body) \n
nonce \n
timestamp
```

Rules, all of which have a test:

- `METHOD` is uppercase, from `X-Forwarded-Method`.
- `SCHEME` is `https` for every configured host; a request arriving as `http` is
  refused before the string is built.
- `HOST` is `X-Forwarded-Host`, lowercased, without a port. A port in the value
  is stripped, and the same stripping happens in the browser so both sides
  agree.
- `REQUEST-TARGET` is `X-Forwarded-Uri`, verbatim: path plus query. No trailing
  `?` when the query is empty.
- `SHA256(body)` is lowercase hex of the exact bytes received, or the digest of
  the empty string for a bodiless request.
- `nonce` and `timestamp` are as sent, with no decoding.
- The separator is a single `\n` and there is no trailing newline.

Build it with a `strings.Builder` preallocated to 256 bytes; do not use
`fmt.Sprintf`, which is both slower and a place for a format verb to drift.

`internal/proof/testdata/canonical.json`:

```json
[
  {
    "name": "get root",
    "method": "GET", "scheme": "https", "host": "aivan-hud.home.arpa",
    "target": "/", "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "nonce": "N1", "timestamp": "1700000000",
    "expected": "aivan-v1\nGET\nhttps://aivan-hud.home.arpa\n/\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nN1\n1700000000"
  },
  {
    "name": "query string matters",
    "method": "GET", "scheme": "https", "host": "aivan-hud.home.arpa",
    "target": "/admin?id=2", "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "nonce": "N1", "timestamp": "1700000000",
    "expected": "aivan-v1\nGET\nhttps://aivan-hud.home.arpa\n/admin?id=2\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nN1\n1700000000"
  },
  {
    "name": "encoded path survives",
    "method": "POST", "scheme": "https", "host": "aivan-hud.home.arpa",
    "target": "/a%20b?y=%2F", "body_sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "nonce": "N2", "timestamp": "1700000001",
    "expected": "aivan-v1\nPOST\nhttps://aivan-hud.home.arpa\n/a%20b?y=%2F\n2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\nN2\n1700000001"
  }
]
```

The third vector's hash is `sha256("hello")`. Verify it when writing the file
rather than trusting this document.

Phase F reads the same file from the browser test. Keep it a flat array of
objects with no nesting, so the JavaScript side needs no parser beyond
`JSON.parse`.

## C2. Algorithms

`internal/proof/verify.go`. Fixed list, keyed off `devices.alg` — never off a
request field (S17).

- `ed25519`: `ed25519.Verify(pub, msg, sig)`, key exactly 32 bytes, signature
  exactly 64. Length mismatch is a denial, not a panic.
- `es256`: `ecdsa.VerifyASN1` with a `P-256` key. The browser's WebCrypto
  `sign({name:'ECDSA',hash:'SHA-256'})` emits ASN.1 DER, so that is the wire
  format. A raw `r||s` signature is refused; do not accept both, because
  accepting both means one of them is untested.

Any other value of `alg` denies with reason `alg_unsupported`. This is S17.

S15: the comparisons the service performs itself (nonce equality in the
database, session token hash) use `crypto/subtle`. Library signature
verification is not re-implemented.

## C3. Nonce issuance

`POST /__aivan/nonce`, body `{"device": "<uuid>"}`.

- Validates the body is a UUID and nothing else. A malformed id is a `400`; this
  is not an oracle, because the id is checked syntactically and never looked up.
- Inserts into `authz.nonces` with `expires_at = now() + AIVAN_NONCE_TTL`.
- Returns `{"nonce": "<base64url 32 bytes>", "expires_at": "<rfc3339>"}`.
- Stores `sha256(nonce)`, never the nonce.
- **Always succeeds** for a syntactically valid device id, whether or not the
  device exists (S14). No database read of `devices` on this path; that is what
  keeps it from being an existence oracle.
- Rate limit: token bucket per source IP (from `X-Forwarded-For` only when the
  peer is in `AIVAN_TRUSTED_PROXY_CIDRS`, otherwise the peer address), 30 per
  minute, burst 10. Over the limit is `429`.
- Table cap: if `authz.nonces` holds more than 100k rows, refuse with `503`.
  The purge ticker arrives in Phase G; until then a `DELETE … WHERE expires_at <
  now()` runs on the same schedule as the cap check, once a minute.

## C4. Verify, in one statement

`ANY /__aivan/verify`. Traefik sends the original method here because
`preserveRequestMethod: true`.

```sql
with consumed as (
  delete from authz.nonces
   where nonce_hash = $1
     and device_id  = $2
     and expires_at > now()
  returning device_id, issued_at
)
select d.id, d.public_key, d.alg, d.revoked_at, d.user_id, d.origin,
       u.username, u.active, c.issued_at,
       coalesce(array_agg(g.name order by g.name)
                filter (where g.name is not null), '{}') as roles
  from consumed c
  join authz.devices d on d.id = c.device_id
  join public.users u  on u.id = d.user_id
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 group by d.id, d.public_key, d.alg, d.revoked_at, d.user_id, d.origin,
          c.issued_at, u.username, u.active;
```

Prepare it once at startup with `pgx.Pool.Prepare`. `$1` is
`sha256(X-Aivan-Nonce)`, `$2` is `X-Aivan-Device` parsed as a UUID. Passing the
device id as a query parameter rather than filtering afterwards is what keeps
the plan a single index probe.

### Order of operations

1. Parse the four proof headers. Missing any of them means no proof, which
   follows the denial matrix in C6.
2. Consume the nonce. No row means `nonce_unknown`, `nonce_expired` or
   `replay` — all reported to the client identically.
3. Check `timestamp` against local time, ±`AIVAN_SKEW`. Older than `issued_at`
   is also a denial (a signature cannot be older than the nonce that made it
   possible).
4. Check `d.origin` equals `X-Forwarded-Host` (lowercased). S21.
5. Check `d.revoked_at is null`. S5's device half arrives here; the session half
   is Phase D.
6. Check `u.active`.
7. Verify the signature with `d.alg` (C2).
8. Evaluate policy (C5).
9. Set headers and return `200`.

Steps 6 and 7 are ordered that way deliberately: an inactive user is refused
without spending CPU on a signature, and the response is identical either way.

`last_seen_at` is **not** written here. A background sweep updates it for
devices seen in the last day; Phase G adds it. A write per verify would break
the one-round-trip budget and is the most tempting mistake in this phase.

### Prepared statement and query counter

Instrument the pool with a counter that increments per `Query`/`Exec`. A test
asserts exactly one statement for a successful verify and zero for a malformed
request that never reaches the database.

## C5. Policy

`internal/policy`. Per host, each route a prefix and a class. Longest prefix
wins; equal length is a startup refusal. A request matching no prefix uses
class `authenticated` and logs `reason=class_defaulted`, because silently
serving something public would be worse than requiring a proof.

Classes in this phase:

| Class | Requirement |
|---|---|
| `public` | no proof; send no `X-Aivan-*` |
| `authenticated` | any active device of an active user |
| `admin` | the above, plus `admin` in the role list |

Role resolution is the `array_agg` in the verify statement — no second query. S7
is the test: user with no groups on an `admin` route is `403`.

`enrollment` is added in Phase F; the config refuses it until then, so a
half-built class cannot be configured.

## C6. Denials

| Case | Status | Notes |
|---|---|---|
| no proof headers, `Accept` contains `text/html` | `302` to `/__aivan/enroll?rd=<urlencoded X-Forwarded-Uri>` | never on a `POST`: redirecting a body loses it |
| no proof headers, anything else | `401` + `WWW-Authenticate: Aivan` | body names the nonce endpoint |
| nonce unknown / expired / replayed | `401` | identical body and timing to the line above |
| timestamp skewed or before `issued_at` | `401` | same body |
| device unknown, revoked, or wrong origin | `401` | same body |
| user inactive | `401` | same body |
| bad signature | `401` | same body |
| algorithm not in the list | `401` | same body; log `reason=alg_unsupported` |
| valid proof, role insufficient | `403` | empty body |
| body over `AIVAN_MAX_BODY` | `413` | empty body |
| database error | `503` | empty body; log the error without the DSN |
| nonce endpoint rate limited | `429` | on `/__aivan/nonce` only |

S14: the `401` body is one constant string, and the service must not vary
status, body length, or header set across the reasons. Write the test as a table
that asserts equality of the full response across all `401` cases.

### Headers on success

```text
X-Aivan-User-Id:     <id>
X-Aivan-User:        <username>
X-Aivan-Device-Id:   <uuid>
X-Aivan-Device-Kind: phone|tablet|browser
X-Aivan-Roles:       admin,free        (sorted, comma separated, no spaces)
X-Aivan-Proof:       nonce
X-Aivan-Request-Id:  <generated>
```

No `X-Aivan-Session`. Usernames containing anything outside `[A-Za-z0-9._@-]`
are refused rather than encoded (spec §6.1); that is a `403` with
`reason=username_unrepresentable`, logged, and it should never happen in
practice because registration validates names.

## C7. Body handling (S18 prep)

`AIVAN_MAX_BODY` is enforced in this phase even though the `413` test is
Phase G:

```go
r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBody)
```

Read the body once, hash it, and keep the hash. On overflow, `MaxBytesError`
maps to `413`. Do not read the body for methods that cannot carry one you hash
(`GET`, `HEAD`, `OPTIONS`, `DELETE`): use the empty-body digest, and make sure
Traefik is not configured to forward a body for those either.

## C8. Tests

Unit tests, no database:

- [ ] Every canonical vector produces `expected` byte for byte.
- [ ] Changing any covered field changes the string (table-driven over method,
      scheme, host, target, body hash, nonce, timestamp). S2.
- [ ] `alg_unsupported` for `rs256`, `none`, `ES256` (case), and empty. S17.
- [ ] ES256 rejects a raw `r||s` signature.
- [ ] Policy: longest prefix wins, equal length refused, unknown prefix defaults
      to `authenticated`, `admin` requires the role.

Integration tests, against the fixture database:

- [ ] A second use of a consumed nonce is refused. S1.
- [ ] A nonce past `expires_at` is refused (injected clock). S3.
- [ ] A timestamp beyond the skew window is refused; one exactly at the boundary
      is accepted. S4.
- [ ] A device bound to a different origin is refused. S21.
- [ ] A revoked device is refused.
- [ ] A user with no groups is refused on an `admin` route. S7.
- [ ] A device of user A presenting user B in any header is still user A. S8.
      (The header is not read at all; assert that.)
- [ ] All `401` cases produce byte-identical responses. S14.
- [ ] Exactly one statement per successful verify; zero for a request rejected
      before the database.

Every security test above must be shown to fail when its guard is removed. Do
that in the commit message: name the guard, the failing test, and the line that
was temporarily deleted.

## C9. Benchmark

`BenchmarkVerify` against a local Postgres using `pgxpool`, Ed25519 key, warm
pool. Report p50/p99 with `go test -bench . -benchtime 20s`.

Exit target: p99 under 5 ms with the database on localhost. If it misses, check
in this order: prepared statement actually prepared (not re-parsed), the origin
and nonce predicates both using the primary key, `array_agg` not spilling, and
whether the connection pool is being re-dialed.

## C10. Exit criteria

- [ ] S1–S4, S7, S8, S14, S15, S17, S19, S21 green, each demonstrated to fail
      without its guard.
- [ ] One statement per verify, asserted.
- [ ] p99 under 5 ms locally, with the `go test -bench` output in the commit.
- [ ] `/__aivan/verify` answers every method, including `HEAD` and `OPTIONS`,
      without a panic.
- [ ] Commit.

## Handoff to Phase D

Phase D adds sessions on top of a working proof path. It needs: the verify
statement's shape, the pool instrumentation, and the denial helpers so the
session path returns the same bodies. It will add the session half of S5, and
S13.

Deliberate omission in this phase: no `sessions` read path, no cookie, no CSRF.
A proof-only gate is a legitimate intermediate state and is worth having green
before adding a second credential.